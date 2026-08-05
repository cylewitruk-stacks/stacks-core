// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Ownership and join ordering for protocol worker threads.

use std::thread::JoinHandle;

/// Owns the long-lived worker threads and enforces their shutdown join order.
pub struct WorkerHandles<PeerResult> {
    relayer: JoinHandle<()>,
    peer: JoinHandle<PeerResult>,
}

impl<PeerResult> WorkerHandles<PeerResult> {
    pub fn new(relayer: JoinHandle<()>, peer: JoinHandle<PeerResult>) -> Self {
        Self { relayer, peer }
    }

    pub fn join(self) -> PeerResult {
        self.relayer.join().unwrap();
        self.peer.join().unwrap()
    }
}
