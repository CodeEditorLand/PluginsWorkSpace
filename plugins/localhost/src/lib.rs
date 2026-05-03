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

use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
};

use http::Uri;
use tauri::{
    plugin::{Builder as PluginBuilder, TauriPlugin},
    Runtime,
};
use tiny_http::{Header, Response as HttpResponse, Server};

pub struct Request {
    url: String,
}

impl Request {
    pub fn url(&self) -> &str {
        &self.url
    }
}

pub struct Response {
    headers: HashMap<String, String>,
}

impl Response {
    pub fn add_header<H: Into<String>, V: Into<String>>(&mut self, header: H, value: V) {
        self.headers.insert(header.into(), value.into());
    }
}

type OnRequest = Option<Box<dyn Fn(&Request, &mut Response) + Send + Sync>>;

/// Land-specific extension-asset resolver. Mounted at the
/// `/Extension/` URL prefix so the workbench's runtime-emitted
/// `@font-face`, `<img>` and webview-resource URLs resolve to the
/// extension-host installation directories on disk.
///
/// The Land Output transform `RewriteIconsStyleSheetURLs` (and the
/// follow-up webview-resource rewrites) emit URLs of the form
/// `<origin>/Extension/<absolute-fs-path>` for extension-contributed
/// assets that live outside the bundled `Static/Application/` tree.
/// This resolver turns those URLs back into filesystem reads,
/// constrained to a small set of allowed roots so a malicious
/// extension cannot exfiltrate the user's filesystem via crafted
/// URLs.
///
/// Allowed roots default to:
///   * the user's home dir + `.land/extensions/`
///   * the user's home dir + `.vscode/extensions/`
///   * an explicit list passed in via `Builder::extension_roots`.
///
/// Reads outside the allowed roots return 403. Path components
/// containing `..` are rejected before any IO. Symlinks are
/// followed but the resolved path must still fall under an
/// allowed root.
fn resolve_extension_path(
    request_path: &str,
    allowed_roots: &[PathBuf],
) -> Option<PathBuf> {
    // Strip the `/Extension/` prefix and URL-decode (basic).
    let stripped = request_path.strip_prefix("/Extension/")?;
    let decoded = url_decode(stripped);

    // The IC-01 transform rewrites `vscode-file://vscode-app/<abs>`
    // to `<origin>/Extension/<abs>`, which on Unix flattens an
    // absolute filesystem path's leading slash into the URL
    // separator after `/Extension/`. Restore the absolute-path
    // indicator before constructing the `PathBuf`:
    //
    //   Unix path:    `/<home>/.land/extensions/<id>/...`
    //   URL emitted:  `<origin>/Extension/<home>/...`
    //   After strip:  `<home>/...`                   (relative!)
    //   After prefix: `/<home>/...`                  (absolute)
    //
    // Windows paths arrive with a drive prefix (`C:/...`) and need
    // no synthetic leading slash; detect by checking the second
    // character for a `:`.
    let absolute_str = if cfg!(windows)
        && decoded
            .chars()
            .nth(1)
            .map(|c| c == ':')
            .unwrap_or(false)
    {
        decoded.into_owned()
    } else {
        format!("/{}", decoded)
    };

    // Reject any traversal segments before touching the filesystem.
    let candidate = PathBuf::from(absolute_str);
    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {}
            _ => return None,
        }
    }

    // Ensure the candidate (after canonicalisation) falls under an
    // allowed root.
    let canonical = fs::canonicalize(&candidate).ok()?;
    for root in allowed_roots {
        if let Ok(canonical_root) = fs::canonicalize(root) {
            if canonical.starts_with(&canonical_root) {
                return Some(canonical);
            }
        }
    }
    None
}

fn url_decode(input: &str) -> std::borrow::Cow<'_, str> {
    if !input.contains('%') {
        return std::borrow::Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(decoded) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                out.push(decoded as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    std::borrow::Cow::Owned(out)
}

fn mime_from_extension(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("js" | "mjs" | "cjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") | Some("map") => "application/json; charset=utf-8",
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("eot") => "application/vnd.ms-fontobject",
        _ => "application/octet-stream",
    }
}

pub struct Builder {
    port: u16,
    host: Option<String>,
    on_request: OnRequest,
    extension_roots: Vec<PathBuf>,
}

impl Builder {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            host: None,
            on_request: None,
            extension_roots: Vec::new(),
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

    /// Register a filesystem root the `/Extension/` URL prefix can
    /// serve from. Multiple roots are permitted; reads must
    /// canonicalise to a path under one of them.
    pub fn extension_root<P: Into<PathBuf>>(mut self, root: P) -> Self {
        self.extension_roots.push(root.into());
        self
    }

    pub fn build<R: Runtime>(mut self) -> TauriPlugin<R> {
        let port = self.port;
        let host = self.host.unwrap_or("localhost".to_string());
        let on_request = self.on_request.take();
        let extension_roots = std::mem::take(&mut self.extension_roots);

        PluginBuilder::new("localhost")
            .setup(move |app, _api| {
                let asset_resolver = app.asset_resolver();
                std::thread::spawn(move || {
                    let server =
                        Server::http(format!("{host}:{port}")).expect("Unable to spawn server");
                    for req in server.incoming_requests() {
                        let path: String = req
                            .url()
                            .parse::<Uri>()
                            .map(|uri| uri.path().into())
                            .unwrap_or_else(|_| req.url().into());

                        // LAND-PATCH: `/Extension/<abs-fs-path>` route.
                        // Serves files from registered extension
                        // roots so workbench-emitted URLs (icon
                        // fonts, webview resources, ...) pointing
                        // at sideloaded extension installation
                        // dirs can be fetched same-origin.
                        if path.starts_with("/Extension/") && !extension_roots.is_empty() {
                            if let Some(resolved) =
                                resolve_extension_path(&path, &extension_roots)
                            {
                                if let Ok(bytes) = fs::read(&resolved) {
                                    let mime = mime_from_extension(&resolved);
                                    let request = Request {
                                        url: req.url().into(),
                                    };
                                    let mut response = Response {
                                        headers: Default::default(),
                                    };
                                    response.add_header("Content-Type", mime);
                                    response
                                        .headers
                                        .insert("Cache-Control".into(), "no-cache".into());
                                    if let Some(on_request) = &on_request {
                                        on_request(&request, &mut response);
                                    }
                                    let mut resp = HttpResponse::from_data(bytes);
                                    for (header, value) in response.headers {
                                        if let Ok(h) =
                                            Header::from_bytes(header.as_bytes(), value)
                                        {
                                            resp.add_header(h);
                                        }
                                    }
                                    let _ = req.respond(resp);
                                    continue;
                                }
                            }
                            // Fall through to 404 below if path
                            // could not be resolved or read.
                            let body = b"404 Not Found".to_vec();
                            let mut resp = HttpResponse::from_data(body);
                            if let Ok(h) = Header::from_bytes(
                                "Content-Type".as_bytes(),
                                "text/plain; charset=utf-8",
                            ) {
                                resp.add_header(h);
                            }
                            let _ = req.respond(resp.with_status_code(404));
                            continue;
                        }

                        #[allow(unused_mut)]
                        if let Some(mut asset) = asset_resolver.get(path) {
                            let request = Request {
                                url: req.url().into(),
                            };
                            let mut response = Response {
                                headers: Default::default(),
                            };

                            response.add_header("Content-Type", asset.mime_type);
                            if let Some(csp) = asset.csp_header {
                                response
                                    .headers
                                    .insert("Content-Security-Policy".into(), csp);
                            }

                            response
                                .headers
                                .insert("Cache-Control".into(), "no-cache".into());

                            if let Some(on_request) = &on_request {
                                on_request(&request, &mut response);
                            }

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
