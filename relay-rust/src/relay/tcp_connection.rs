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

use log::*;
use mio::net::TcpStream;
use mio::{Interest, Token};
use rand::random;
use std::cell::RefCell;
use std::cmp;
use std::io;
use std::num::Wrapping;
use std::rc::{Rc, Weak};

use super::binary;
use super::client::{Client, ClientChannel};
use super::connection::{Connection, ConnectionId};
use super::ipv4_header::Ipv4Header;
use super::ipv4_packet::{Ipv4Packet, MAX_PACKET_LENGTH};
use super::packet_source::PacketSource;
use super::packetizer::Packetizer;
use super::selector::{Readiness, Selector};
use super::stream_buffer::StreamBuffer;
use super::tcp_header::{self, TcpHeader, TcpHeaderMut};
use super::transport_header::{TransportHeader, TransportHeaderMut};

const TAG: &str = "TcpConnection";

// same value as GnirehtetService.MTU in the client
const MTU: u16 = 0x4000;
// 20 bytes for IP headers, 20 bytes for TCP headers
const MAX_PAYLOAD_LENGTH: u16 = MTU - 20 - 20 as u16;

pub struct TcpConnection {
    self_weak: Weak<RefCell<TcpConnection>>,
    id: ConnectionId,
    client: Weak<RefCell<Client>>,
    stream: TcpStream,
    token: Token,
    // last readiness reported by the selector, until an operation returns WouldBlock
    readable: bool,
    writable: bool,
    client_to_network: StreamBuffer,
    network_to_client: Packetizer,
    packet_for_client_length: Option<u16>,
    closed: bool,
    tcb: Tcb,
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
    #[allow(clippy::needless_pass_by_value)] // semantically, headers are consumed
    pub fn create(
        selector: &mut Selector,
        id: ConnectionId,
        client: Weak<RefCell<Client>>,
        ipv4_header: Ipv4Header,
        transport_header: TransportHeader,
    ) -> io::Result<Rc<RefCell<Self>>> {
        cx_info!(target: TAG, id, "Open");
        let stream = Self::create_stream(&id)?;

        let tcp_header = Self::tcp_header_of_transport(transport_header);

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

        let packetizer = Packetizer::new(&ipv4_header, &shrinked_transport_header);

        let rc = Rc::new(RefCell::new(Self {
            self_weak: Weak::new(),
            id,
            client,
            stream,
            token: Token(0), // default value, will be set afterwards
            readable: false,
            writable: false,
            client_to_network: StreamBuffer::new(4 * MAX_PACKET_LENGTH),
            network_to_client: packetizer,
            packet_for_client_length: None,
            closed: false,
            tcb: Tcb::new(),
        }));

        {
            let mut self_ref = rc.borrow_mut();

            // keep a shared reference to this
            self_ref.self_weak = Rc::downgrade(&rc);

            let rc2 = rc.clone();
            // must annotate selector type: https://stackoverflow.com/a/44004103/1987178
            let handler = move |selector: &mut Selector, readiness| {
                rc2.borrow_mut().on_ready(selector, readiness)
            };
            // the stream becomes writable once connected
            let token = selector.register(
                &mut self_ref.stream,
                handler,
                Interest::READABLE | Interest::WRITABLE,
            )?;
            self_ref.token = token;
        }
        Ok(rc)
    }

    fn create_stream(id: &ConnectionId) -> io::Result<TcpStream> {
        TcpStream::connect(id.rewritten_destination().into())
    }

    fn remove_from_router(&self) {
        // route is embedded in router which is embedded in client: the client necessarily exists
        let client_rc = self.client.upgrade().expect("Expected client not found");
        let mut client = client_rc.borrow_mut();
        client.router().remove(self);
    }

    fn on_ready(&mut self, selector: &mut Selector, readiness: Readiness) {
        self.readable |= readiness.readable;
        self.writable |= readiness.writable;
        if self.closed {
            return;
        }
        if self.tcb.state == TcpState::SynSent {
            if self.writable {
                self.check_connected(selector);
            }
        } else {
            if self.writable && self.may_write() {
                self.process_send(selector);
            }
            if !self.closed && self.readable && self.may_read() {
                self.process_receive(selector);
            }
        }
        if self.closed {
            // on_ready is not called from the router, so the connection must remove itself
            self.remove_from_router();
        }
    }

    /// Request a call to on_ready() if some I/O may now be performed
    ///
    /// To be used when the state changes outside of on_ready() (the client may be borrowed).
    fn wake_if_ready(&self, selector: &mut Selector) {
        let connecting = self.tcb.state == TcpState::SynSent;
        if (self.writable && (connecting || self.may_write())) || (self.readable && self.may_read())
        {
            selector.wake(self.token);
        }
    }

    fn check_connected(&mut self, selector: &mut Selector) {
        // a writable event does not guarantee that the connection succeeded
        match self.stream.take_error() {
            Ok(None) => (),
            Ok(Some(err)) | Err(err) => {
                cx_error!(target: TAG, self.id, "Cannot connect: {}", err);
                self.close(selector);
                return;
            }
        }
        match self.stream.peer_addr() {
            Ok(_) => self.process_connect(selector),
            // not connected yet, wait for the next writable event
            Err(err) if err.kind() == io::ErrorKind::NotConnected => self.writable = false,
            Err(err) => {
                cx_error!(target: TAG, self.id, "Cannot connect: {}", err);
                self.close(selector);
            }
        }
    }

    fn process_send(&mut self, selector: &mut Selector) {
        let mut written = 0;
        while !self.client_to_network.is_empty() {
            match self.client_to_network.write_to(&mut self.stream) {
                Ok(0) => {
                    cx_error!(target: TAG, self.id, "Cannot write: the socket accepts no data");
                    self.close(selector);
                    return;
                }
                Ok(w) => written += w,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.writable = false;
                    break;
                }
                Err(err) => {
                    cx_error!(
                        target: TAG,
                        self.id,
                        "Cannot write: [{:?}] {}",
                        err.kind(),
                        err
                    );
                    self.send_empty_packet_to_client(selector, tcp_header::FLAG_RST);
                    self.close(selector);
                    return;
                }
            }
        }
        if written == 0 {
            return;
        }

        self.tcb.acknowledgement_number += Wrapping(written as u32);
        if self.tcb.fin_received && self.client_to_network.is_empty() {
            let client_rc = self.client.upgrade().expect("Expected client not found");
            let mut client = client_rc.borrow_mut();
            cx_debug!(
                target: TAG,
                self.id,
                "No more pending data, process the pending FIN"
            );
            self.do_handle_fin(selector, &mut client.channel());
        } else {
            cx_debug!(
                target: TAG,
                self.id,
                "Sending ACK {} to client",
                self.tcb.numbers()
            );
            self.send_empty_packet_to_client(selector, tcp_header::FLAG_ACK);
        }
    }

    fn process_receive(&mut self, selector: &mut Selector) {
        assert!(
            self.packet_for_client_length.is_none(),
            "A pending packet was not sent"
        );
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
        match self
            .network_to_client
            .packetize_read(&mut self.stream, max_payload_length)
        {
            Ok(Some(ipv4_packet)) => {
                match Self::send_to_client(&self.client, selector, &ipv4_packet) {
                    Ok(_) => {
                        let len = ipv4_packet.payload().unwrap().len();
                        cx_debug!(
                            target: TAG,
                            self.id,
                            "Packet ({} bytes) sent to client {}",
                            len,
                            self.tcb.numbers()
                        );
                        self.tcb.sequence_number += Wrapping(len as u32);
                        // read one chunk per iteration, so that connections are processed in turn
                        selector.wake(self.token);
                    }
                    Err(_) => {
                        // ask to the client to pull when its buffer is not full
                        let client_rc = self.client.upgrade().expect("Expected client not found");
                        let mut client = client_rc.borrow_mut();
                        let self_rc = self.self_weak.upgrade().unwrap();
                        client.register_pending_packet_source(self_rc);
                        self.packet_for_client_length = Some(ipv4_packet.length());
                    }
                };
            }
            Ok(None) => {
                self.eof(selector);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => self.readable = false,
            Err(err) => {
                cx_error!(
                    target: TAG,
                    self.id,
                    "Cannot read: [{:?}] {}",
                    err.kind(),
                    err
                );
                self.send_empty_packet_to_client(selector, tcp_header::FLAG_RST);
                self.close(selector);
            }
        }
    }

    fn process_connect(&mut self, selector: &mut Selector) {
        assert_eq!(self.tcb.state, TcpState::SynSent);
        self.tcb.state = TcpState::SynReceived;
        cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        self.send_empty_packet_to_client(selector, tcp_header::FLAG_SYN | tcp_header::FLAG_ACK);
        self.tcb.sequence_number += Wrapping(1); // SYN counts for 1 byte
    }

    fn send_to_client(
        client: &Weak<RefCell<Client>>,
        selector: &mut Selector,
        ipv4_packet: &Ipv4Packet,
    ) -> io::Result<()> {
        let client_rc = client.upgrade().expect("Expected client not found");
        let mut client = client_rc.borrow_mut();
        client.send_to_client(selector, &ipv4_packet)
    }

    /// Borrow self.client and send empty packet to it
    ///
    /// To be used if called by on_ready() (so the client is not borrowed yet).
    fn send_empty_packet_to_client(&mut self, selector: &mut Selector, flags: u16) {
        let client_rc = self.client.upgrade().expect("Expected client not found");
        let mut client = client_rc.borrow_mut();
        self.reply_empty_packet_to_client(selector, &mut client.channel(), flags)
    }

    /// Send empty packet to the client channel (that already borrows the client)
    ///
    /// To be used if called by send_to_network() (called by the client, so it is already
    /// borrowed).
    fn reply_empty_packet_to_client(
        &mut self,
        selector: &mut Selector,
        client_channel: &mut ClientChannel,
        flags: u16,
    ) {
        let ipv4_packet = Self::create_empty_response_packet(
            &self.id,
            &mut self.network_to_client,
            &self.tcb,
            flags,
        );
        if let Err(err) = client_channel.send_to_client(selector, &ipv4_packet) {
            // losing such an empty packet will not break the TCP connection
            cx_warn!(
                target: TAG,
                self.id,
                "Cannot send packet to client: {}",
                err
            );
        }
    }

    fn eof(&mut self, selector: &mut Selector) {
        self.send_empty_packet_to_client(selector, tcp_header::FLAG_FIN | tcp_header::FLAG_ACK);
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

    fn handle_packet(
        &mut self,
        selector: &mut Selector,
        client_channel: &mut ClientChannel,
        ipv4_packet: &Ipv4Packet,
    ) {
        let tcp_header = Self::tcp_header_of_packet(ipv4_packet);
        if self.tcb.state == TcpState::Init {
            self.handle_first_packet(selector, client_channel, ipv4_packet);
            return;
        }

        if tcp_header.is_syn() {
            self.handle_duplicate_syn(selector, client_channel, ipv4_packet);
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
                self.reply_empty_packet_to_client(selector, client_channel, tcp_header::FLAG_ACK);
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
            self.close(selector);
            return;
        }

        if tcp_header.is_ack() {
            cx_debug!(
                target: TAG,
                self.id,
                "Client acked {}",
                tcp_header.acknowledgement_number()
            );

            self.handle_ack(selector, client_channel, ipv4_packet);
        }

        if tcp_header.is_fin() {
            self.handle_fin(selector, client_channel);
        }

        if let Some(fin_sequence_number) = self.tcb.fin_sequence_number {
            if tcp_header.acknowledgement_number() == fin_sequence_number + 1 {
                cx_debug!(target: TAG, self.id, "Received ACK of FIN");
                self.handle_fin_ack(selector);
            }
        }
    }

    fn handle_first_packet(
        &mut self,
        selector: &mut Selector,
        client_channel: &mut ClientChannel,
        ipv4_packet: &Ipv4Packet,
    ) {
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
            self.reply_empty_packet_to_client(selector, client_channel, tcp_header::FLAG_RST);
            self.close(selector);
        }
    }

    fn handle_duplicate_syn(
        &mut self,
        selector: &mut Selector,
        client_channel: &mut ClientChannel,
        ipv4_packet: &Ipv4Packet,
    ) {
        let tcp_header = Self::tcp_header_of_packet(ipv4_packet);
        let their_sequence_number = tcp_header.sequence_number();
        if self.tcb.state == TcpState::SynSent {
            // the connection is not established yet, we can accept this packet as if it were the
            // first SYN
            self.tcb.syn_sequence_number = their_sequence_number;
            self.tcb.acknowledgement_number = Wrapping(their_sequence_number) + Wrapping(1);
        } else if their_sequence_number != self.tcb.syn_sequence_number {
            // duplicate SYN with different sequence number
            self.reply_empty_packet_to_client(selector, client_channel, tcp_header::FLAG_RST);
            self.close(selector);
        }
    }

    fn handle_fin(&mut self, selector: &mut Selector, client_channel: &mut ClientChannel) {
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
            self.do_handle_fin(selector, client_channel);
        }
        // otherwise, the FIN will be processed once client_to_network is empty
    }

    fn do_handle_fin(&mut self, selector: &mut Selector, client_channel: &mut ClientChannel) {
        self.tcb.acknowledgement_number += Wrapping(1); // received FIN counts for 1 byte

        if self.tcb.state == TcpState::Established {
            self.reply_empty_packet_to_client(
                selector,
                client_channel,
                tcp_header::FLAG_FIN | tcp_header::FLAG_ACK,
            );
            self.tcb.fin_sequence_number = Some(self.tcb.sequence_number.0);
            self.tcb.sequence_number += Wrapping(1); // FIN counts for 1 byte
            // the connection will be closed by RAII, so switch immediately to LastAck
            // (bypass CloseWait)
            self.tcb.state = TcpState::LastAck;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        } else if self.tcb.state == TcpState::FinWait1 {
            self.reply_empty_packet_to_client(selector, client_channel, tcp_header::FLAG_ACK);
            self.tcb.state = TcpState::Closing;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
        } else if self.tcb.state == TcpState::FinWait2 {
            self.reply_empty_packet_to_client(selector, client_channel, tcp_header::FLAG_ACK);
            self.close(selector);
        } else {
            cx_warn!(
                target: TAG,
                self.id,
                "Received FIN was state was {:?}",
                self.tcb.state
            );
        }
    }

    fn handle_fin_ack(&mut self, selector: &mut Selector) {
        if self.tcb.state == TcpState::LastAck || self.tcb.state == TcpState::Closing {
            self.close(selector);
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

    fn handle_ack(
        &mut self,
        _selector: &mut Selector,
        _client_channel: &mut ClientChannel,
        ipv4_packet: &Ipv4Packet,
    ) {
        cx_debug!(target: TAG, self.id, "handle_ack()");
        if self.tcb.state == TcpState::SynReceived {
            self.tcb.state = TcpState::Established;
            cx_debug!(target: TAG, self.id, "State = {:?}", self.tcb.state);
            return;
        }

        if log_enabled!(target: TAG, Level::Trace) {
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
        Self::update_headers(packetizer.empty_transport_header_mut(), tcb, flags);
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
        if log_enabled!(target: TAG, Level::Trace) {
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
        if self.packet_for_client_length.is_some() {
            // a packet is already pending
            return false;
        }
        self.tcb.remaining_client_window() > 0
    }

    fn may_write(&self) -> bool {
        !self.client_to_network.is_empty()
    }
}

impl Connection for TcpConnection {
    fn id(&self) -> &ConnectionId {
        &self.id
    }

    fn send_to_network(
        &mut self,
        selector: &mut Selector,
        client_channel: &mut ClientChannel,
        ipv4_packet: &Ipv4Packet,
    ) {
        self.handle_packet(selector, client_channel, ipv4_packet);
        if !self.closed {
            self.wake_if_ready(selector);
        }
    }

    fn close(&mut self, selector: &mut Selector) {
        cx_info!(target: TAG, self.id, "Close");
        self.closed = true;
        if let Err(err) = selector.deregister(&mut self.stream, self.token) {
            // do not panic, this can happen in mio
            // see <https://github.com/Genymobile/gnirehtet/issues/136>
            cx_warn!(
                target: TAG,
                self.id,
                "Fail to deregister TCP stream: {:?}",
                err
            );
        }
        // socket will be closed by RAII
    }

    fn is_expired(&self) -> bool {
        // no external timeout expiration
        false
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

impl PacketSource for TcpConnection {
    fn get(&mut self) -> Option<Ipv4Packet> {
        if let Some(len) = self.packet_for_client_length {
            Some(self.network_to_client.inflate(len))
        } else {
            None
        }
    }

    fn next(&mut self, selector: &mut Selector) {
        let len = self
            .packet_for_client_length
            .expect("next() called on empty packet source");
        cx_debug!(
            target: TAG,
            self.id,
            "Deferred packet ({} bytes) sent to client {}",
            len,
            self.tcb.numbers()
        );
        self.tcb.sequence_number += Wrapping(u32::from(len));
        self.packet_for_client_length = None;
        self.wake_if_ready(selector);
    }
}
