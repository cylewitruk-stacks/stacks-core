// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Binary consensus serialization codec for the Stacks blockchain.
//!
//! The trait, error type, and primitive impls live here. `stacks-common`
//! temporarily re-exports this surface while callers migrate.

#[macro_use]
pub mod macros;

pub mod address;
pub mod codec;
pub mod p2p;
pub mod primitives;
pub mod strings;

// TODO: Re-enable these modules once their dependencies no longer force
// `stacks-codec -> stacks-common`, which would cycle with the temporary
// `stacks-common -> stacks-codec` re-export bridge.
// pub mod transaction;

pub use codec::*;
