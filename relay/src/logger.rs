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

use std::io::{self};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::fmt::writer::MakeWriterExt;

/// Print the logs to stdout, and the errors to stderr
///
/// The logs are filtered by the `RUST_LOG` environment variable (`info` by default).
pub fn init() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_timer(ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".to_owned()))
        .with_writer(io::stderr.with_max_level(Level::ERROR).or_else(io::stdout))
        .init();
}
