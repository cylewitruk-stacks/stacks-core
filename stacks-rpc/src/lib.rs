// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#[macro_use]
extern crate stacks_common;

pub mod config;
pub mod error;
pub mod models;
mod server;

pub use server::{prepare_axum_rpc_server, PreparedAxumRpcServer};
