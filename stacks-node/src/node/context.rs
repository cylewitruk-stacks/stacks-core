// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use stacks::burnchains::Burnchain;

use crate::node::runtime::Globals;
use crate::{Config, EventDispatcher};

/// Era-neutral values required to assemble an epoch-aware node.
pub struct SpawnContext<Directive> {
    config: Config,
    burnchain: Burnchain,
    shared: Globals<Directive>,
    events: EventDispatcher,
    is_miner: bool,
}

impl<Directive> SpawnContext<Directive> {
    pub fn new(
        config: Config,
        burnchain: Burnchain,
        shared: Globals<Directive>,
        events: EventDispatcher,
        is_miner: bool,
    ) -> Self {
        Self {
            config,
            burnchain,
            shared,
            events,
            is_miner,
        }
    }

    pub fn shared(&self) -> Globals<Directive> {
        self.shared.clone()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn burnchain(&self) -> &Burnchain {
        &self.burnchain
    }

    pub fn events(&self) -> EventDispatcher {
        self.events.clone()
    }

    pub fn is_miner(&self) -> bool {
        self.is_miner
    }

    pub fn into_parts(self) -> (Config, Burnchain, Globals<Directive>, EventDispatcher, bool) {
        (
            self.config,
            self.burnchain,
            self.shared,
            self.events,
            self.is_miner,
        )
    }
}
