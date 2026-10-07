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

use std::io;
use std::net::{self, Ipv4Addr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;
use tokio::task::coop;
use tokio::time::{self, Instant};
use tracing::Level;

use super::binary;
use super::client::ClientSender;
use super::connection::ConnectionId;
use super::ipv4_packet::{Ipv4Packet, MAX_PACKET_LENGTH};
use super::outbox::Outbox;
use super::packetizer::Packetizer;

const TAG: &str = "UdpConnection";

const IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Maximum size of the datagrams waiting for the client queue
///
/// Beyond it, datagrams wait in the socket buffer (and the system drops them when it is full).
const MAX_BACKLOG: usize = 16 * MAX_PACKET_LENGTH;

pub struct UdpConnection {
    id: ConnectionId,
    // packets for the client, sent in order
    outbox: Outbox,
    network_to_client: Packetizer,
}

enum Event {
    Packet(Option<Vec<u8>>),
    Readable(io::Result<()>),
    // false if the client is closed
    Flushed(bool),
    Expired,
}

impl UdpConnection {
    /// Relay datagrams between the client and the destination, until the connection is idle
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
        match Self::create_socket(&connection.id) {
            Ok(socket) => {
                if Self::send_to_network(&connection.id, &socket, first_packet).await {
                    connection.process(&socket, &mut inbound).await;
                }
            }
            Err(err) => cx_error!(target: TAG, connection.id, "Cannot open socket: {}", err),
        }
        cx_info!(target: TAG, connection.id, "Close");
    }

    fn new(id: ConnectionId, client: ClientSender, first_packet: &mut [u8]) -> Self {
        let ipv4_packet = Ipv4Packet::parse(first_packet);
        let (ipv4_header, transport_header) = ipv4_packet.headers();
        let packetizer = Packetizer::new(&ipv4_header, &transport_header.expect("No transport"));
        Self {
            id,
            outbox: Outbox::new(client),
            network_to_client: packetizer,
        }
    }

    fn create_socket(id: &ConnectionId) -> io::Result<UdpSocket> {
        let socket = net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect(id.rewritten_destination())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }

    async fn process(&mut self, socket: &UdpSocket, inbound: &mut Receiver<Vec<u8>>) {
        let idle = time::sleep(IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            let may_read = self.outbox.bytes() < MAX_BACKLOG;
            let has_backlog = !self.outbox.is_empty();
            let event = tokio::select! {
                packet = inbound.recv() => Event::Packet(packet),
                result = socket.readable(), if may_read => Event::Readable(result),
                open = self.outbox.flush(), if has_backlog => Event::Flushed(open),
                _ = &mut idle => Event::Expired,
            };
            let open = match event {
                Event::Packet(Some(raw)) => Self::send_to_network(&self.id, socket, raw).await,
                // the client is closed
                Event::Packet(None) => false,
                Event::Readable(Ok(())) => {
                    let open = self.receive(socket);
                    // readiness does not consume the task budget, let the other tasks run
                    coop::consume_budget().await;
                    open
                }
                Event::Readable(Err(err)) => {
                    cx_error!(target: TAG, self.id, "Socket error: {}", err);
                    false
                }
                Event::Flushed(open) => open,
                Event::Expired => {
                    cx_debug!(target: TAG, self.id, "Idle for too long");
                    false
                }
            };
            if !open {
                return;
            }
            idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
        }
    }

    /// Send the payload of a packet from the client, return false if the connection must close
    async fn send_to_network(id: &ConnectionId, socket: &UdpSocket, mut raw: Vec<u8>) -> bool {
        let ipv4_packet = Ipv4Packet::parse(&mut raw);
        let payload = ipv4_packet.payload().expect("No payload");
        match socket.send(payload).await {
            Ok(_) => true,
            Err(err) => {
                cx_error!(target: TAG, id, "Cannot write: [{:?}] {}", err.kind(), err);
                false
            }
        }
    }

    /// Forward a datagram to the client, return false if the connection must close
    fn receive(&mut self, socket: &UdpSocket) -> bool {
        let mut source = socket;
        let ipv4_packet = match self.network_to_client.packetize(&mut source) {
            Ok(ipv4_packet) => ipv4_packet,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return true,
            Err(err) => {
                cx_error!(target: TAG, self.id, "Cannot read: [{:?}] {}", err.kind(), err);
                return false;
            }
        };
        if tracing::enabled!(target: TAG, Level::TRACE) {
            cx_trace!(
                target: TAG,
                self.id,
                "{}",
                binary::build_packet_string(ipv4_packet.raw())
            );
        }
        let length = ipv4_packet.length();
        let open = self.outbox.push(ipv4_packet.raw().to_vec());
        cx_debug!(
            target: TAG,
            self.id,
            "Packet ({} bytes) sent to client",
            length
        );
        open
    }
}
