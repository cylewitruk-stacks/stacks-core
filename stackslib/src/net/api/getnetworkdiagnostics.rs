// Copyright (C) 2026 Stacks Labs
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Protected snapshot of the native libp2p network. High-cardinality peer and
//! signer observations live here, never in Prometheus labels or public peer
//! metadata.

use regex::{Captures, Regex};
use stacks_common::types::net::PeerHost;

use crate::monitoring::libp2p_network_diagnostics;
use crate::net::http::{
    parse_json, Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

pub const PATH: &str = "/v3/network/diagnostics";

#[derive(Clone)]
pub struct RPCNetworkDiagnosticsRequestHandler {
    auth: Option<String>,
}

impl RPCNetworkDiagnosticsRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self { auth }
    }
}

impl HttpRequest for RPCNetworkDiagnosticsRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/network/diagnostics$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        PATH
    }

    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        let Some(password) = &self.auth else {
            // Keep the sensitive endpoint absent unless privileged RPC auth is
            // explicitly configured.
            return Err(Error::Http(404, "Not Found".into()));
        };
        if preamble.headers.get("authorization") != Some(password) {
            return Err(Error::Http(401, "Unauthorized".into()));
        }
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "network diagnostics requires an empty request body".to_owned(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNetworkDiagnosticsRequestHandler {
    fn restart(&mut self) {}

    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        _node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let response = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&libp2p_network_diagnostics())?;
        Ok((response, body))
    }
}

impl HttpResponse for RPCNetworkDiagnosticsRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let snapshot: serde_json::Value = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(snapshot)
    }
}

impl StacksHttpRequest {
    pub fn new_get_network_diagnostics(host: PeerHost, auth: &str) -> Self {
        let mut request = StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            PATH.into(),
            HttpRequestContents::new(),
        )
        .expect("infallible native-network diagnostics request");
        request.add_header("authorization".into(), auth.into());
        request
    }
}

impl StacksHttpResponse {
    pub fn decode_network_diagnostics(self) -> Result<serde_json::Value, NetError> {
        let contents = self.get_http_payload_ok()?;
        contents.try_into().map_err(NetError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_protected_and_has_a_stable_path() {
        assert_eq!(PATH, "/v3/network/diagnostics");
        assert_eq!(
            RPCNetworkDiagnosticsRequestHandler::new(Some("secret".into())).metrics_identifier(),
            PATH
        );
    }
}
