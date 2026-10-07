/*
 * Copyright (C) 2017 Genymobile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use rand::random;
use std::cmp;
use std::io;
use std::net::SocketAddr;
use std::num::Wrapping;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::task::coop;
use tracing::Level;

use super::binary;
use super::client::ClientSender;
use super::connection::ConnectionId;
use super::datagram::{TryRead, TryWrite};
use super::ipv4_packet::{Ipv4Packet, MAX_PACKET_LENGTH};
use super::outbox::Outbox;
use super::packetizer::Packetizer;
use super::stream_buffer::StreamBuffer;
use super::tcp_header::{self, TcpHeader, TcpHeaderMut};
use super::transport_header::{TransportHeader, TransportHeaderMut};

const TAG: &str = "TcpConnection";

// same value as GnirehtetService.MTU in the client
const MTU: u16 = 0x4000;
// 20 bytes for IP headers, 20 bytes for TCP headers
const MAX_PAYLOAD_LENGTH: u16 = MTU - 20 - 20;

pub struct TcpConnection {
    id: ConnectionId,
    // packets for the client, sent in order
    outbox: Outbox,
    client_to_network: StreamBuffer,
    network_to_client: Packetizer,
    closed: bool,
    tcb: Tcb,
}

enum Event {
    Packet(Option<Vec<u8>>),
    Readable(io::Result<()>),
    Writable(io::Result<()>),
    // false if the client is closed
    Flushed(bool),
}

// Transport Control Block
struct Tcb {
    state: TcpState,
    syn_sequence_number: u32,
    sequence_number: Wrapping<u32>,
    acknowledgement_number: Wrapping<u32>,
    their_acknowledgement_number: u32,
    fin_sequence_number: Option<u32>,
    fin_received: bool,
    client_window: u16,
}

// See RFC793: <https://tools.ietf.org/html/rfc793#page-23>
#[derive(Debug, PartialEq, Eq)]
enum TcpState {
    Init,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
    Closing,
    FinWait1,
    FinWait2,
}

impl TcpState {
    fn is_connected(&self) -> bool {
        self != &TcpState::Init && self != &TcpState::SynSent && self != &TcpState::SynReceived
    }

    fn is_closed(&self) -> bool {
        self == &TcpState::FinWait1
            || self == &TcpState::FinWait2
            || self == &TcpState::Closing
            || self == &TcpState::LastAck
    }
}

impl Tcb {
    fn new() -> Self {
        Self {
            state: TcpState::Init,
            syn_sequence_number: 0,
            sequence_number: Wrapping(0),
            acknowledgement_number: Wrapping(0),
            their_acknowledgement_number: 0,
            fin_sequence_number: None,
            fin_received: false,
            client_window: 0,
        }
    }

    fn remaining_client_window(&self) -> u16 {
        let wrapped_remaining = Wrapping(self.their_acknowledgement_number)
            + Wrapping(u32::from(self.client_window))
            - self.sequence_number;
        let remaining = wrapped_remaining.0;
        if remaining <= u32::from(self.client_window) {
            remaining as u16
        } else {
            0
        }
    }

    fn numbers(&self) -> String {
        format!(
            "(seq={}, ack={})",
            self.sequence_number, self.acknowledgement_number
        )
    }
}

impl TcpConnection {
    /// Relay a TCP connection initiated by the client, until it is closed
    ///
    /// `inbound` receives the next packets sent by the client for this connection.
    pub async fn run(
        id: ConnectionId,
        client: ClientSender,
        mut first_packet: Vec<u8>,
        mut inbound: Receiver<Vec<u8>>,
    ) {
        cx_info!(target: TAG, id, "Open");
        let mut connection = Self::new(id, client, &mut first_packet);
        connection.handle_raw_packet(&mut first_packet);
        if !connection.closed
            && let Some(stream) = connection.connect(&mut inbound).await
        {
            connection.process(&stream, &mut inbound).await;
        }
        // deliver the last packets (RST, ACK of a FIN...) before terminating
        while !connection.outbox.is_empty() && connection.outbox.flush().await {}
        // the network socket is closed when dropped
        cx_info!(target: TAG, connection.id, "Close");
    }

    fn new(id: ConnectionId, client: ClientSender, first_packet: &mut [u8]) -> Self {
        let ipv4_packet = Ipv4Packet::parse(first_packet);
        let (ipv4_header, transport_header) = ipv4_packet.headers();
        let tcp_header = Self::tcp_header_of_transport(transport_header.expect("No transport"));

        // shrink the TCP options to pass a minimal refrence header to the packetizer
        let mut shrinked_tcp_header_raw = [0u8; 20];
        shrinked_tcp_header_raw.copy_from_slice(&tcp_header.raw()[..20]);
        let mut shrinked_tcp_header_data = tcp_header.data().clone();
        {
            let mut shrinked_tcp_header =
                shrinked_tcp_header_data.bind_mut(&mut shrinked_tcp_header_raw);
            shrinked_tcp_header.shrink_options();
            assert_eq!(20, shrinked_tcp_header.header_length());
        }

        let shrinked_transport_header = shrinked_tcp_header_data
            .bind(&shrinked_tcp_header_raw)
            .into();

        Self {
            id,
            outbox: Outbox::new(client),
            client_to_network: StreamBuffer::new(4 * MAX_PACKET_LENGTH),
            network_to_client: Packetizer::new(&ipv4_header, &shrinked_transport_header),
            closed: false,
            tcb: Tcb::new(),
        }
    }

    /// Connect to the destination, while handling the packets the client sends meanwhile
    async fn connect(&mut self, inbound: &mut Receiver<Vec<u8>>) -> Option<TcpStream> {
        let connect = TcpStream::connect(SocketAddr::from(self.id.rewritten_destination()));
        tokio::pin!(connect);
        loop {
            tokio::select! {
                result = &mut connect => {
                    return match result {
                        Ok(stream) => {
                            self.process_connect();
                            Some(stream)
                        }
                        Err(err) => {
                            cx_error!(target: TAG, self.id, "Cannot connect: {}", err);
                            None
                        }
                    };
                }
                packet = inbound.recv() => match packet {
                    Some(mut raw) => {
                        self.handle_raw_packet(&mut raw);
                        if self.closed {
                            return None;
                        }
                    }
                    // the client is closed
                    None => return None,
                },
            }
        }
    }

    async fn process(&mut self, stream: &TcpStream, inbound: &mut Receiver<Vec<u8>>) {
        while !self.closed {
            let may_read = self.may_read();
            let may_write = self.may_write();
            let has_backlog = !self.outbox.is_empty();
            let event = tokio::select! {
                packet = inbound.recv() => Event::Packet(packet),
                result = stream.readable(), if may_read => Event::Readable(result),
                result = stream.writable(), if may_write => Event::Writable(result),
                open = self.outbox.flush(), if has_backlog => Event::Flushed(open),
            };
            match event {
                Event::Packet(Some(mut raw)) => self.handle_raw_packet(&mut raw),
                // the client is closed
                Event::Packet(None) | Event::Flushed(false) => return,
                Event::Readable(Ok(())) => {
                    self.process_receive(stream);
                    // readiness does not consume the task budget, let the other tasks run
                    coop::consume_budget().await;
                }
                Event::Writable(Ok(())) => self.process_send(stream),
                Event::Readable(Err(err)) | Event::Writable(Err(err)) => {
                    cx_error!(target: TAG, self.id, "Socket error: {}", err);
                    self.send_empty_packet_to_client(tcp_header::FLAG_RST);
                    self.close();
                }
                Event::Flushed(true) => (),
            }
        }
    }

    fn close(&mut self) {
        self.closed = true;
    }

    fn process_send(&mut self, stream: &TcpStream) {
        let mut written = 0;
        while !self.client_to_network.is_empty() {
            match self.client_to_network.write_to(&mut TryWrite(stream)) {
                Ok(0) => {
                    cx_error!(target: TAG, self.id, "Cannot write: the socket accepts no data");
                    self.close();
                    return;
                }
                Ok(w) => written += w,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    cx_error!(
                        target: TAG,
                        self.id,
                        "Cannot write: [{:?}] {}",
                        err.kind(),
                        err
                    );
                    self.send_empty_packet_to_client(tcp_header::FLAG_RST);
                    self.close();
                    return;
                }
            }
        }
        if written == 0 {
            return;
        }

        self.tcb.acknowledgement_number += Wrapping(written as u32);
        if self.tcb.fin_received && self.client_to_network.is_empty() {
            cx_debug!(
                target: TAG,
                self.id,
                "No more pending data, process the pending FIN"
            );
            self.do_handle_fin();
        } else {
            cx_debug!(
                target: TAG,
                self.id,
                "Sending ACK {} to client",
                self.tcb.numbers()
            );
            self.send_empty_packet_to_client(tcp_header::FLAG_ACK);
        }
    }

    fn process_receive(&mut self, stream: &TcpStream) {
        assert!(self.outbox.is_empty(), "Packets for the client are waiting");
        let remaining_client_window = self.tcb.remaining_client_window();
        assert!(
            remaining_client_window > 0,
            "process_received() must not be called when window == 0"
        );
        let max_payload_length =
            Some(cmp::min(remaining_client_window, MAX_PAYLOAD_LENGTH) as usize);
        Self::update_headers(
            self.network_to_client.transport_header_mut(),
            &self.tcb,
            tcp_header::FLAG_ACK | tcp_header::FLAG_PSH,
        );
        let packet = match self
            .network_to_client
            .packetize_read(&mut TryRead(stream), max_payload_length)
        {
            Ok(Some(ipv4_packet)) => (
                ipv4_packet.raw().to_vec(),
                ipv4_packet.payload().unwrap().len() as u16,
            ),
            Ok(None) => {
                self.eof();
                return;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
            Err(err) => {
                cx_error!(
                    target: TAG,
                    self.id,
                    "Cannot read: [{:?}] {}",
                    err.kind(),
                    err
                );
                self.send_empty_packet_to_client(tcp_header::FLAG_RST);
                self.close();
                return;
            }
        };

        let (raw, payload_length) = packet;
        // queued packets are never dropped: they count as sent
        self.tcb.sequence_number += Wrapping(u32::from(payload_length));
        cx_debug!(
            target: TAG,
            self.id,
            "Packet ({} bytes) sent to client {}",
            payload_length,
            self.tcb.numbers()
        );
        // if it does not fit in the client queue, stop reading from the network until it does
        if !self.outbox.push(raw) {
            self.close();
        }
    }

    fn process_connect(&mut self) {
        assert_eq!(self.tcb.state, TcpState::SynSent);
        self.tcb.state = TcpState::SynReceived;
        cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        self.send_empty_packet_to_client(tcp_header::FLAG_SYN | tcp_header::FLAG_ACK);
        self.tcb.sequence_number += Wrapping(1); // SYN counts for 1 byte
    }

    fn send_empty_packet_to_client(&mut self, flags: u16) {
        let raw = Self::create_empty_response_packet(
            &self.id,
            &mut self.network_to_client,
            &self.tcb,
            flags,
        )
        .raw()
        .to_vec();
        if !self.outbox.push(raw) {
            self.close();
        }
    }

    fn eof(&mut self) {
        self.send_empty_packet_to_client(tcp_header::FLAG_FIN | tcp_header::FLAG_ACK);
        self.tcb.fin_sequence_number = Some(self.tcb.sequence_number.0);
        self.tcb.sequence_number += Wrapping(1); // FIN counts for 1 byte
        self.tcb.state = if self.tcb.state == TcpState::CloseWait {
            TcpState::LastAck
        } else {
            TcpState::FinWait1
        };
        cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
    }

    #[inline]
    fn tcp_header_of_transport(transport_header: TransportHeader) -> TcpHeader {
        if let TransportHeader::Tcp(tcp_header) = transport_header {
            tcp_header
        } else {
            panic!("Not a TCP header");
        }
    }

    #[inline]
    fn tcp_header_of_transport_mut(transport_header: TransportHeaderMut) -> TcpHeaderMut {
        if let TransportHeaderMut::Tcp(tcp_header) = transport_header {
            tcp_header
        } else {
            panic!("Not a TCP header");
        }
    }

    #[inline]
    fn tcp_header_of_packet<'a>(ipv4_packet: &'a Ipv4Packet) -> TcpHeader<'a> {
        if let Some(TransportHeader::Tcp(tcp_header)) = ipv4_packet.transport_header() {
            tcp_header
        } else {
            panic!("Not a TCP packet");
        }
    }

    fn update_headers(transport_header: TransportHeaderMut, tcb: &Tcb, flags: u16) {
        let mut tcp_header = Self::tcp_header_of_transport_mut(transport_header);
        tcp_header.set_sequence_number(tcb.sequence_number.0);
        tcp_header.set_acknowledgement_number(tcb.acknowledgement_number.0);
        tcp_header.set_flags(flags);
    }

    fn handle_raw_packet(&mut self, raw: &mut [u8]) {
        let ipv4_packet = Ipv4Packet::parse(raw);
        self.handle_packet(&ipv4_packet);
    }

    fn handle_packet(&mut self, ipv4_packet: &Ipv4Packet) {
        let tcp_header = Self::tcp_header_of_packet(ipv4_packet);
        if self.tcb.state == TcpState::Init {
            self.handle_first_packet(ipv4_packet);
            return;
        }

        if tcp_header.is_syn() {
            self.handle_duplicate_syn(ipv4_packet);
            return;
        }

        let expected_packet =
            (self.tcb.acknowledgement_number + Wrapping(self.client_to_network.size() as u32)).0;
        if tcp_header.sequence_number() != expected_packet {
            // ignore packet already received or out-of-order, retransmission is already
            // managed by both sides
            cx_warn!(
                target: TAG,
                self.id,
                "Ignoring packet {} (acking {}); expecting {}; flags={}",
                tcp_header.sequence_number(),
                tcp_header.acknowledgement_number(),
                expected_packet,
                tcp_header.flags()
            );
            if !tcp_header.is_rst() && self.tcb.state.is_connected() {
                // RFC 793: an unacceptable segment must be answered with an ACK. Keepalive
                // probes (sequence number one below the expected one) rely on it: without a
                // reply, the client aborts the connection after a few probes.
                self.send_empty_packet_to_client(tcp_header::FLAG_ACK);
            }
            return;
        }

        self.tcb.client_window = tcp_header.window();
        self.tcb.their_acknowledgement_number = tcp_header.acknowledgement_number();

        cx_debug!(
            target: TAG,
            self.id,
            "Receiving expected packet {} (flags={})",
            tcp_header.sequence_number(),
            tcp_header.flags()
        );

        if tcp_header.is_rst() {
            self.close();
            return;
        }

        if tcp_header.is_ack() {
            cx_debug!(
                target: TAG,
                self.id,
                "Client acked {}",
                tcp_header.acknowledgement_number()
            );

            self.handle_ack(ipv4_packet);
        }

        if tcp_header.is_fin() {
            self.handle_fin();
        }

        if let Some(fin_sequence_number) = self.tcb.fin_sequence_number
            && tcp_header.acknowledgement_number() == fin_sequence_number + 1
        {
            cx_debug!(target: TAG, self.id, "Received ACK of FIN");
            self.handle_fin_ack();
        }
    }

    fn handle_first_packet(&mut self, ipv4_packet: &Ipv4Packet) {
        cx_debug!(target: TAG, self.id, "handle_first_packet()");
        let tcp_header = Self::tcp_header_of_packet(ipv4_packet);
        if tcp_header.is_syn() {
            let their_sequence_number = tcp_header.sequence_number();
            self.tcb.acknowledgement_number = Wrapping(their_sequence_number) + Wrapping(1);
            self.tcb.syn_sequence_number = their_sequence_number;

            self.tcb.sequence_number = Wrapping(random::<u32>());
            cx_debug!(
                target: TAG,
                self.id,
                "Initialized seq={}; ack={}",
                self.tcb.sequence_number,
                self.tcb.acknowledgement_number
            );
            self.tcb.client_window = tcp_header.window();
            self.tcb.state = TcpState::SynSent;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        } else {
            cx_warn!(
                target: TAG,
                self.id,
                "Unexpected first packet {}; acking {}; flags={}",
                tcp_header.sequence_number(),
                tcp_header.acknowledgement_number(),
                tcp_header.flags()
            );
            // make a RST in the window client
            self.tcb.sequence_number = Wrapping(tcp_header.acknowledgement_number());
            self.send_empty_packet_to_client(tcp_header::FLAG_RST);
            self.close();
        }
    }

    fn handle_duplicate_syn(&mut self, ipv4_packet: &Ipv4Packet) {
        let tcp_header = Self::tcp_header_of_packet(ipv4_packet);
        let their_sequence_number = tcp_header.sequence_number();
        if self.tcb.state == TcpState::SynSent {
            // the connection is not established yet, we can accept this packet as if it were the
            // first SYN
            self.tcb.syn_sequence_number = their_sequence_number;
            self.tcb.acknowledgement_number = Wrapping(their_sequence_number) + Wrapping(1);
        } else if their_sequence_number != self.tcb.syn_sequence_number {
            // duplicate SYN with different sequence number
            self.send_empty_packet_to_client(tcp_header::FLAG_RST);
            self.close();
        }
    }

    fn handle_fin(&mut self) {
        cx_debug!(
            target: TAG,
            self.id,
            "Received a FIN from the client {}",
            self.tcb.numbers()
        );

        self.tcb.fin_received = true;
        if self.client_to_network.is_empty() {
            cx_debug!(
                target: TAG,
                self.id,
                "No pending data, process the FIN immediately"
            );
            self.do_handle_fin();
        }
        // otherwise, the FIN will be processed once client_to_network is empty
    }

    fn do_handle_fin(&mut self) {
        self.tcb.acknowledgement_number += Wrapping(1); // received FIN counts for 1 byte

        if self.tcb.state == TcpState::Established {
            self.send_empty_packet_to_client(tcp_header::FLAG_FIN | tcp_header::FLAG_ACK);
            self.tcb.fin_sequence_number = Some(self.tcb.sequence_number.0);
            self.tcb.sequence_number += Wrapping(1); // FIN counts for 1 byte
            // the connection will be closed by RAII, so switch immediately to LastAck
            // (bypass CloseWait)
            self.tcb.state = TcpState::LastAck;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        } else if self.tcb.state == TcpState::FinWait1 {
            self.send_empty_packet_to_client(tcp_header::FLAG_ACK);
            self.tcb.state = TcpState::Closing;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        } else if self.tcb.state == TcpState::FinWait2 {
            self.send_empty_packet_to_client(tcp_header::FLAG_ACK);
            self.close();
        } else {
            cx_warn!(
                target: TAG,
                self.id,
                "Received FIN was state was {:?}",
                self.tcb.state
            );
        }
    }

    fn handle_fin_ack(&mut self) {
        if self.tcb.state == TcpState::LastAck || self.tcb.state == TcpState::Closing {
            self.close();
        } else if self.tcb.state == TcpState::FinWait1 {
            self.tcb.state = TcpState::FinWait2;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        } else if self.tcb.state != TcpState::FinWait2 {
            cx_warn!(
                target: TAG,
                self.id,
                "Received FIN ACK while state was {:?}",
                self.tcb.state
            );
        }
    }

    fn handle_ack(&mut self, ipv4_packet: &Ipv4Packet) {
        cx_debug!(target: TAG, self.id, "handle_ack()");
        if self.tcb.state == TcpState::SynReceived {
            self.tcb.state = TcpState::Established;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
            return;
        }

        if tracing::enabled!(target: TAG, Level::TRACE) {
            cx_trace!(
                target: TAG,
                self.id,
                "{}",
                binary::build_packet_string(ipv4_packet.raw())
            );
        }

        let payload = ipv4_packet.payload().expect("No payload");
        if payload.is_empty() {
            // no data to transmit
            return;
        }

        if self.client_to_network.remaining() < payload.len() {
            cx_warn!(target: TAG, self.id, "Not enough space, dropping packet");
            return;
        }

        self.client_to_network.read_from(payload);
        // data will be ACKed once written to the network socket
    }

    fn create_empty_response_packet<'a>(
        id: &ConnectionId,
        packetizer: &'a mut Packetizer,
        tcb: &Tcb,
        flags: u16,
    ) -> Ipv4Packet<'a> {
        Self::update_headers(packetizer.transport_header_mut(), tcb, flags);
        cx_debug!(
            target: TAG,
            id,
            "Forging empty response (flags={}) {}",
            flags,
            tcb.numbers()
        );
        if (flags & tcp_header::FLAG_ACK) != 0 {
            cx_debug!(target: TAG, id, "Acking {}", tcb.numbers());
        }
        let ipv4_packet = packetizer.packetize_empty_payload();
        if tracing::enabled!(target: TAG, Level::TRACE) {
            cx_trace!(
                target: TAG,
                id,
                "{}",
                binary::build_packet_string(ipv4_packet.raw())
            );
        }
        ipv4_packet
    }

    fn may_read(&self) -> bool {
        if !self.tcb.state.is_connected() || self.tcb.state.is_closed() {
            return false;
        }
        if !self.outbox.is_empty() {
            // wait for the client queue
            return false;
        }
        self.tcb.remaining_client_window() > 0
    }

    fn may_write(&self) -> bool {
        !self.client_to_network.is_empty()
    }
}
