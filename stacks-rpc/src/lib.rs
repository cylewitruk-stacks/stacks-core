// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#[macro_use]
extern crate stacks_common;

mod blocking;
mod chainstate_read;
mod config;
mod error;
mod extractors;
mod models;
mod routes;
mod server;
mod state;

pub use config::{AxumRpcConfig, ChainstateReadSpec};
pub use error::{ApiErrorCode, ErrorBody, ErrorResponse};
pub use models::{
    AccountProofs, AccountResponse, BlockProposalStatus, BlockProposalSubmitResponse,
    BurnBlockInfo, InfoResponse, StacksTipInfo,
};
pub use server::{prepare_axum_rpc_server, PreparedAxumRpcServer};

#[cfg(test)]
mod tests;
