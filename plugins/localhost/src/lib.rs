// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Expose your apps assets through a localhost server instead of the default custom protocol.
//!
//! **Note: This plugins brings considerable security risks and you should only use it if you know what your are doing. If in doubt, use the default custom protocol implementation.**

#![doc(
    html_logo_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png",
    html_favicon_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png"
)]

use std::collections::HashMap;

use http::Uri;
use tauri::{
    plugin::{Builder as PluginBuilder, TauriPlugin},
    Runtime,
};
use tiny_http::{Header, Response as HttpResponse, Server};

pub struct Request {
    url: String,
    body: Vec<u8>,
    method: String,
}

impl Request {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn method(&self) -> &str {
        &self.method
    }
}

pub struct Response {
    headers: HashMap<String, String>,
    status_code: u16,
    body: Vec<u8>,
    handled: bool,
}

impl Response {
    pub fn add_header<H: Into<String>, V: Into<String>>(&mut self, header: H, value: V) {
        self.headers.insert(header.into(), value.into());
    }

    pub fn set_status(&mut self, code: u16) {
        self.status_code = code;
    }

    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
    }

    /// Mark as handled — the plugin will send this response instead of
    /// looking up a static asset. Use for proxy routes, health checks, etc.
    pub fn set_handled(&mut self, handled: bool) {
        self.handled = handled;
    }
}

type OnRequest = Option<Box<dyn Fn(&Request, &mut Response) + Send + Sync>>;

pub struct Builder {
    port: u16,
    host: Option<String>,
    on_request: OnRequest,
}

impl Builder {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            host: None,
            on_request: None,
        }
    }

    // Change the host the plugin binds to. Defaults to `localhost`.
    pub fn host<H: Into<String>>(mut self, host: H) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn on_request<F: Fn(&Request, &mut Response) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_request.replace(Box::new(f));
        self
    }

    pub fn build<R: Runtime>(mut self) -> TauriPlugin<R> {
        let port = self.port;
        let host = self.host.unwrap_or("localhost".to_string());
        let on_request = self.on_request.take();

        PluginBuilder::new("localhost")
            .setup(move |app, _api| {
                let asset_resolver = app.asset_resolver();
                std::thread::spawn(move || {
                    let server =
                        Server::http(format!("{host}:{port}")).expect("Unable to spawn server");
                    for mut req in server.incoming_requests() {
                        let path: String = req
                            .url()
                            .parse::<Uri>()
                            .map(|uri| uri.path().into())
                            .unwrap_or_else(|_| req.url().into());

                        // Read request body (for proxy routes, webhooks, etc.)
                        let mut body_bytes = Vec::new();
                        let _ = std::io::Read::read_to_end(req.as_reader(), &mut body_bytes);

                        let request = Request {
                            url: req.url().into(),
                            body: body_bytes,
                            method: req.method().to_string(),
                        };
                        let mut response = Response {
                            headers: Default::default(),
                            status_code: 200,
                            body: Vec::new(),
                            handled: false,
                        };

                        // Call on_request first — it may handle proxy routes
                        if let Some(on_request) = &on_request {
                            on_request(&request, &mut response);
                        }

                        // If on_request marked as handled, send custom response
                        if response.handled {
                            let mut resp = HttpResponse::from_data(response.body)
                                .with_status_code(response.status_code);
                            for (header, value) in response.headers {
                                if let Ok(h) = Header::from_bytes(header.as_bytes(), value) {
                                    resp.add_header(h);
                                }
                            }
                            let _ = req.respond(resp);
                            continue;
                        }

                        // Standard asset serving
                        #[allow(unused_mut)]
                        if let Some(mut asset) = asset_resolver.get(path) {
                            response.add_header("Content-Type", asset.mime_type);
                            if let Some(csp) = asset.csp_header {
                                response
                                    .headers
                                    .insert("Content-Security-Policy".into(), csp);
                            }

                            response
                                .headers
                                .insert("Cache-Control".into(), "no-cache".into());

                            let mut resp = HttpResponse::from_data(asset.bytes);
                            for (header, value) in response.headers {
                                if let Ok(h) = Header::from_bytes(header.as_bytes(), value) {
                                    resp.add_header(h);
                                }
                            }
                            req.respond(resp).expect("unable to setup response");
                        }
                    }
                });
                Ok(())
            })
            .build()
    }
}
