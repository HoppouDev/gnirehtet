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
use mio::event::{Event, Source};
use mio::{Events, Interest, Poll, Token};
use slab::Slab;
use std::io;
use std::mem;
use std::rc::Rc;
use std::time::Duration;

const TAG: &str = "Selector";

/// Readiness reported to an event handler.
///
/// mio only provides edge-triggered notifications, so handlers must remember the readiness they
/// received until the corresponding operation returns `WouldBlock`. Error and close notifications
/// are folded into both flags: the actual read or write reports what happened.
#[derive(Clone, Copy, Debug, Default)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
}

impl Readiness {
    fn from_event(event: &Event) -> Self {
        let error = event.is_error();
        Self {
            readable: event.is_readable() || event.is_read_closed() || error,
            writable: event.is_writable() || event.is_write_closed() || error,
        }
    }
}

pub trait EventHandler {
    fn on_ready(&self, selector: &mut Selector, readiness: Readiness);
}

impl<F> EventHandler for F
where
    F: Fn(&mut Selector, Readiness),
{
    fn on_ready(&self, selector: &mut Selector, readiness: Readiness) {
        self(selector, readiness);
    }
}

pub struct Selector {
    poll: Poll,
    handlers: Slab<Rc<dyn EventHandler>>,
    // tokens to be removed after all the current poll events are executed
    tokens_to_remove: Vec<Token>,
    // handlers to call again (with no new readiness) once the current events are executed
    wakes: Vec<Token>,
}

impl Selector {
    pub fn create() -> io::Result<Self> {
        Ok(Self {
            poll: Poll::new()?,
            handlers: Slab::with_capacity(1024),
            tokens_to_remove: Vec::new(),
            wakes: Vec::new(),
        })
    }

    pub fn register<S, H>(
        &mut self,
        source: &mut S,
        handler: H,
        interest: Interest,
    ) -> io::Result<Token>
    where
        S: Source + ?Sized,
        H: EventHandler + 'static,
    {
        let token = Token(self.handlers.insert(Rc::new(handler)));
        if let Err(err) = self.poll.registry().register(source, token, interest) {
            // remove the token we just added
            self.handlers.remove(token.0);
            Err(err)
        } else {
            Ok(token)
        }
    }

    pub fn deregister<S>(&mut self, source: &mut S, token: Token) -> io::Result<()>
    where
        S: Source + ?Sized,
    {
        self.poll.registry().deregister(source)?;
        // remove them before next poll()
        self.tokens_to_remove.push(token);
        Ok(())
    }

    /// Call the handler of `token` again after the current events, without new readiness.
    ///
    /// This lets a handler resume work that was blocked by something other than its socket (a
    /// full client buffer, a closed TCP window...) without being re-entered from the code that
    /// unblocked it.
    pub fn wake(&mut self, token: Token) {
        self.wakes.push(token);
    }

    pub fn has_wakes(&self) -> bool {
        !self.wakes.is_empty()
    }

    fn clean_removed_tokens(&mut self) {
        for &token in &self.tokens_to_remove {
            self.handlers.remove(token.0);
        }
        self.tokens_to_remove.clear();
    }

    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        // pending wakes must run without waiting for new events
        let timeout = if self.wakes.is_empty() {
            timeout
        } else {
            Some(Duration::ZERO)
        };
        self.poll.poll(events, timeout)
    }

    pub fn run_handlers(&mut self, events: &Events) {
        for event in events {
            debug!(target: TAG, "event={:?}", event);
            let handler = self
                .handlers
                .get(event.token().0)
                .expect("Token not found")
                .clone();
            handler.on_ready(self, Readiness::from_event(event));
        }

        // wakes requested while running these ones are executed on the next iteration
        let mut wakes = mem::take(&mut self.wakes);
        wakes.sort_unstable();
        wakes.dedup();
        for token in wakes {
            // the handler may have been removed since the wake was requested
            if let Some(handler) = self.handlers.get(token.0).cloned() {
                handler.on_ready(self, Readiness::default());
            }
        }

        // remove the tokens marked as removed
        self.clean_removed_tokens();
    }
}
