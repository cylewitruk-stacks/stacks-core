// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

use crate::deps_common::bitcoin::util::hash::Sha256dHash;

pub const NO_PARAMS: &[&dyn ToSql] = &[];

impl FromSql for Sha256dHash {
    fn column_result(value: ValueRef) -> FromSqlResult<Sha256dHash> {
        let hex_str = value.as_str()?;
        let hash = Sha256dHash::from_hex(hex_str).map_err(|_e| FromSqlError::InvalidType)?;
        Ok(hash)
    }
}

impl ToSql for Sha256dHash {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let hex_str = self.be_hex_string();
        Ok(hex_str.into())
    }
}
