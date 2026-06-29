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

use clarity::vm::representations::PRINCIPAL_DATA_REGEX_STRING;
use clarity::vm::types::PrincipalData;
use regex::{Captures, Regex};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::to_hex;

use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse,
};
use crate::net::rpc_services::{self, AccountView, ProofBytes, RpcServiceError};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountEntryResponse {
    pub balance: String,
    pub locked: String,
    pub unlock_height: u64,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub balance_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub nonce_proof: Option<String>,
}

impl From<AccountView> for AccountEntryResponse {
    fn from(account: AccountView) -> Self {
        Self {
            balance: hex_u128(account.balance),
            locked: hex_u128(account.locked),
            unlock_height: account.unlock_height,
            nonce: account.nonce,
            balance_proof: legacy_proof(account.balance_proof),
            nonce_proof: legacy_proof(account.nonce_proof),
        }
    }
}

fn hex_u128(value: u128) -> String {
    format!("0x{}", to_hex(&value.to_be_bytes()))
}

fn legacy_proof(proof: ProofBytes) -> Option<String> {
    match proof {
        ProofBytes::NotRequested => None,
        ProofBytes::Missing => Some(String::new()),
        ProofBytes::Present(bytes) => Some(format!("0x{}", to_hex(&bytes))),
    }
}

#[derive(Clone)]
pub struct RPCGetAccountRequestHandler {
    pub account: Option<PrincipalData>,
}
impl RPCGetAccountRequestHandler {
    pub fn new() -> Self {
        Self { account: None }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetAccountRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/accounts/(?P<principal>{})$",
            *PRINCIPAL_DATA_REGEX_STRING
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/accounts/:principal"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }

        let account = if let Some(value) = captures.name("principal") {
            PrincipalData::parse(value.into())
                .map_err(|_e| Error::DecodeError("Failed to parse `principal` field".to_string()))?
        } else {
            return Err(Error::DecodeError(
                "Missing in request path: `principal`".into(),
            ));
        };

        self.account = Some(account);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetAccountRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.account = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip_req = contents.tip_request();
        let account = self
            .account
            .take()
            .ok_or(NetError::SendError("Missing `account`".into()))?;
        let with_proof = contents.get_with_proof();
        let account_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                rpc_services::get_account(sortdb, chainstate, &account, &tip_req, with_proof)
            });

        let account = match account_res {
            Ok(account) => AccountEntryResponse::from(account),
            Err(RpcServiceError::BadRequest(msg)) => {
                return StacksHttpResponse::new_error(&preamble, &HttpBadRequest::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
            Err(RpcServiceError::NotFound(msg)) => {
                return StacksHttpResponse::new_error(&preamble, &HttpNotFound::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
            Err(RpcServiceError::Internal(msg)) => {
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&account)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetAccountRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let account: AccountEntryResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(account)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request for an account
    pub fn new_getaccount(
        host: PeerHost,
        principal: PrincipalData,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/accounts/{}", &principal),
            HttpRequestContents::new()
                .for_tip(tip_req)
                .query_arg("proof".into(), if with_proof { "1" } else { "0" }.into()),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_account_entry_response(self) -> Result<AccountEntryResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: AccountEntryResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::AccountEntryResponse;
    use crate::net::rpc_services::{AccountView, ProofBytes};

    #[test]
    fn account_view_preserves_legacy_missing_proof_shape() {
        let response = AccountEntryResponse::from(AccountView {
            balance: 42,
            locked: 0,
            unlock_height: 0,
            nonce: 3,
            balance_proof: ProofBytes::Missing,
            nonce_proof: ProofBytes::Present(vec![0xab, 0xcd]),
        });

        assert_eq!(response.balance, "0x0000000000000000000000000000002a");
        assert_eq!(response.locked, "0x00000000000000000000000000000000");
        assert_eq!(response.balance_proof, Some(String::new()));
        assert_eq!(response.nonce_proof, Some("0xabcd".to_string()));
    }
}
