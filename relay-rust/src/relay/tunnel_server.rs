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
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time;

use super::client;

const TAG: &str = "TunnelServer";

pub async fn bind(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)).await
}

/// Accept clients and relay each of them in its own task
pub async fn serve(listener: TcpListener) {
    let mut next_client_id = 0u32;
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let id = next_client_id;
                next_client_id += 1;
                info!(target: TAG, "Client #{} connected", id);
                tokio::spawn(async move {
                    client::run(id, stream).await;
                    info!(target: TAG, "Client #{} disconnected", id);
                });
            }
            Err(err) => {
                error!(target: TAG, "Cannot accept client: {}", err);
                // do not spin if the error persists (e.g. too many open files)
                time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
