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

use std::collections::VecDeque;
use std::pin::Pin;
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::mpsc::error::{SendError, TrySendError};

use super::client::ClientSender;

type Reserve = Pin<Box<dyn Future<Output = Result<OwnedPermit<Vec<u8>>, SendError<()>>> + Send>>;

/// Packets of a connection waiting for room in the client queue
///
/// Packets are sent to the client in order and never dropped. A slot freed in the client queue
/// goes to the connections waiting for one first, in turn, so a connection must wait (`flush()`)
/// as soon as one of its packets does not fit.
pub struct Outbox {
    client: ClientSender,
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    // kept across calls to flush(), so that the connection keeps its turn in the client queue
    reserve: Option<Reserve>,
}

impl Outbox {
    pub fn new(client: ClientSender) -> Self {
        Self {
            client,
            packets: VecDeque::new(),
            bytes: 0,
            reserve: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Size of the packets waiting, in bytes
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Send a packet to the client, or keep it until `flush()` sends it
    ///
    /// Return false if the client is closed.
    pub fn push(&mut self, packet: Vec<u8>) -> bool {
        if self.packets.is_empty() {
            match self.client.try_send(packet) {
                Ok(()) => (),
                Err(TrySendError::Full(packet)) => self.push_back(packet),
                Err(TrySendError::Closed(_)) => return false,
            }
        } else if self.client.is_closed() {
            return false;
        } else {
            // keep the order
            self.push_back(packet);
        }
        true
    }

    /// Wait for room in the client queue, then send as many waiting packets as possible
    ///
    /// Must not be called when empty. It is cancel safe: no packet is lost, and the turn in the
    /// client queue is kept for the next call. Return false if the client is closed.
    pub async fn flush(&mut self) -> bool {
        let client = &self.client;
        let reserve = self
            .reserve
            .get_or_insert_with(|| Box::pin(client.clone().reserve_owned()));
        let result = reserve.as_mut().await;
        self.reserve = None;
        let Ok(permit) = result else {
            return false;
        };
        let packet = self.pop_front().expect("No packet waiting");
        permit.send(packet);

        while let Some(packet) = self.pop_front() {
            match self.client.try_send(packet) {
                Ok(()) => (),
                Err(TrySendError::Full(packet)) => {
                    self.push_front(packet);
                    break;
                }
                Err(TrySendError::Closed(_)) => return false,
            }
        }
        true
    }

    fn push_back(&mut self, packet: Vec<u8>) {
        self.bytes += packet.len();
        self.packets.push_back(packet);
    }

    fn push_front(&mut self, packet: Vec<u8>) {
        self.bytes += packet.len();
        self.packets.push_front(packet);
    }

    fn pop_front(&mut self) -> Option<Vec<u8>> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.len();
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn keep_order_when_client_queue_is_full() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut outbox = Outbox::new(sender);

        assert!(outbox.push(vec![1]));
        // the client queue is full: the next packets wait, in order
        assert!(outbox.push(vec![2, 2]));
        assert!(outbox.push(vec![3]));
        assert_eq!(3, outbox.bytes());

        assert_eq!(Some(vec![1]), receiver.recv().await);
        assert!(outbox.flush().await);
        assert_eq!(Some(vec![2, 2]), receiver.recv().await);
        assert!(outbox.flush().await);
        assert_eq!(Some(vec![3]), receiver.recv().await);
        assert!(outbox.is_empty());
        assert_eq!(0, outbox.bytes());
    }

    #[tokio::test]
    async fn report_closed_client() {
        let (sender, receiver) = mpsc::channel(1);
        let mut outbox = Outbox::new(sender);
        assert!(outbox.push(vec![1]));
        assert!(outbox.push(vec![2]));

        drop(receiver);
        assert!(!outbox.flush().await);
        assert!(!outbox.push(vec![3]));
    }
}
