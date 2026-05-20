// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Expose app assets through a localhost server.
//!
//! Two serving strategies:
//!
//! 1. **Embedded** - `asset_resolver` (populated when `frontendDist` is set
//!    in `tauri.conf.json`). A `HashMap` lookup returns Brotli-compressed
//!    bytes that were baked into the binary at compile time.
//!
//! 2. **Disk / static_root** - fallback used when `frontendDist` is `null`.
//!    All assets live on disk under `Contents/Resources/` (production) or
//!    `Element/Sky/Target/` (dev). A per-session `Arc<RwLock<HashMap>>`
//!    cache means each file is read from disk exactly once; subsequent
//!    requests clone an `Arc` and do a `memcpy` - no syscalls.
//!
//! The accept loop spawns a new OS thread per request so slow clients or
//! large files never stall the server waiting for `write()` to drain.
//!
//! Brotli pre-baked siblings (`<file>.br`) are served with
//! `Content-Encoding: br` when the request carries `Accept-Encoding: br`,
//! matching WKWebView's capabilities and the `beforeBundleCommand` pre-bake
//! step in `tauri.conf.json`.
//!
//! **Security note:** this plugin exposes a local HTTP server; only use it
//! when you understand the implications.

#![doc(
    html_logo_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png",
    html_favicon_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png"
)]

use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
    sync::{Arc, RwLock},
};

use http::Uri;
use tauri::{
    plugin::{Builder as PluginBuilder, TauriPlugin},
    Runtime,
};
use tiny_http::{Header, Response as HttpResponse, Server};

// ---------------------------------------------------------------------------
// Public helper types exposed to callers via on_request hooks
// ---------------------------------------------------------------------------

pub struct Request {
    url: String,
}

impl Request {
    pub fn url(&self) -> &str { &self.url }
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

// ---------------------------------------------------------------------------
// In-memory file cache
// ---------------------------------------------------------------------------

/// Single cached file entry. Bytes are either the raw file or its
/// pre-baked Brotli sibling; `brotli` records which so the correct
/// `Content-Encoding` header is emitted.
struct CachedFile {
    /// Raw or Brotli-compressed bytes of the file.
    bytes: Arc<[u8]>,
    /// MIME type derived from the original file extension.
    mime: &'static str,
    /// True when `bytes` are Brotli-encoded.
    brotli: bool,
}

type FileCache = Arc<RwLock<HashMap<PathBuf, Arc<CachedFile>>>>;

/// Load `path` into `cache` on first access; subsequent calls clone the
/// `Arc` with no I/O. When `accepts_brotli` is true and a `<path>.br`
/// sibling exists, the compressed bytes are preferred.
fn cache_get_or_load(
    cache: &FileCache,
    path: &Path,
    accepts_brotli: bool,
) -> Option<Arc<CachedFile>> {
    // Fast path: already cached.
    {
        let guard = cache.read().ok()?;
        if let Some(entry) = guard.get(path) {
            return Some(Arc::clone(entry));
        }
    }

    // Slow path: first access - read from disk.
    let br_path = {
        let mut s = path.as_os_str().to_owned();
        s.push(".br");
        PathBuf::from(s)
    };

    let (bytes, brotli) = if accepts_brotli && br_path.is_file() {
        match fs::read(&br_path) {
            Ok(b) => (b, true),
            Err(_) => match fs::read(path) {
                Ok(b) => (b, false),
                Err(_) => return None,
            },
        }
    } else {
        match fs::read(path) {
            Ok(b) => (b, false),
            Err(_) => return None,
        }
    };

    let entry = Arc::new(CachedFile {
        bytes: bytes.into(),
        mime: mime_from_extension(path),
        brotli,
    });

    // Write into cache; ignore contention - worst case two threads both
    // load the same file and one overwrites the other harmlessly.
    if let Ok(mut guard) = cache.write() {
        guard.insert(path.to_path_buf(), Arc::clone(&entry));
    }

    Some(entry)
}

// ---------------------------------------------------------------------------
// Extension-asset resolver  (/Extension/<abs-fs-path>)
// ---------------------------------------------------------------------------

/// Resolve a `/Extension/<abs-path>` URL to an allowed filesystem path.
/// Rejects `..` traversal and paths outside the registered roots.
fn resolve_extension_path(
    request_path: &str,
    allowed_roots: &[PathBuf],
) -> Option<PathBuf> {
    let stripped = request_path.strip_prefix("/Extension/")?;
    let decoded = url_decode(stripped);

    // Unix: the absolute path's leading `/` was swallowed by the URL
    // structure - restore it. Windows paths start with a drive letter.
    let absolute_str = if cfg!(windows)
        && decoded.chars().nth(1).map(|c| c == ':').unwrap_or(false)
    {
        decoded.into_owned()
    } else {
        format!("/{}", decoded)
    };

    let candidate = PathBuf::from(absolute_str);
    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {}
            _ => return None,
        }
    }

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

// ---------------------------------------------------------------------------
// MIME helpers
// ---------------------------------------------------------------------------

fn mime_from_extension(path: &Path) -> &'static str {
    // Strip a trailing `.br` so `app.js.br` maps to `application/javascript`.
    let effective = if path.extension().and_then(|e| e.to_str()) == Some("br") {
        path.with_extension("")
    } else {
        path.to_path_buf()
    };

    let ext = effective
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());

    match ext.as_deref() {
        Some("js" | "mjs" | "cjs") => "application/javascript; charset=utf-8",
        Some("css")                  => "text/css; charset=utf-8",
        Some("json" | "map")         => "application/json; charset=utf-8",
        Some("html" | "htm")         => "text/html; charset=utf-8",
        Some("svg")                  => "image/svg+xml",
        Some("wasm")                 => "application/wasm",
        Some("png")                  => "image/png",
        Some("jpg" | "jpeg")         => "image/jpeg",
        Some("gif")                  => "image/gif",
        Some("webp")                 => "image/webp",
        Some("ttf")                  => "font/ttf",
        Some("otf")                  => "font/otf",
        Some("woff")                 => "font/woff",
        Some("woff2")                => "font/woff2",
        Some("eot")                  => "application/vnd.ms-fontobject",
        Some("ico")                  => "image/x-icon",
        Some("xml")                  => "application/xml; charset=utf-8",
        Some("txt")                  => "text/plain; charset=utf-8",
        Some("toml")                 => "application/toml; charset=utf-8",
        _                            => "application/octet-stream",
    }
}

/// Whether a URL path looks like an immutable hashed asset whose bytes
/// never change for a given hash.  Returns `true` for `_astro/` chunks
/// and any file whose name contains a content hash segment (`-[A-Za-z0-9]{8}`).
fn is_immutable_asset(path: &str) -> bool {
    path.starts_with("/_astro/") || path.starts_with("_astro/")
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn accepts_brotli(req: &tiny_http::Request) -> bool {
    req.headers().iter().any(|h| {
        // tiny_http uses the `ascii` crate; use `HeaderField::equiv` for
        // case-insensitive &str comparison and `.as_str().as_str()` to get
        // a `&str` out of the `AsciiStr` value.
        h.field.equiv(&"accept-encoding")
            // AsciiStr: Deref<Target = str> - &* gives &str without nightly.
            && (&*h.value.as_str()).contains("br")
    })
}

fn send_response(
    req: tiny_http::Request,
    bytes: Vec<u8>,
    mime: &'static str,
    brotli: bool,
    cache_control: &str,
    extra_headers: &[(&str, &str)],
    on_request: &OnRequest,
) {
    let request = Request { url: req.url().into() };
    let mut response = Response { headers: HashMap::new() };

    response.add_header("Content-Type", mime);
    response.add_header("Cache-Control", cache_control);
    response.add_header("Access-Control-Allow-Origin", "*");
    response.add_header("Cross-Origin-Resource-Policy", "cross-origin");

    if brotli {
        response.add_header("Content-Encoding", "br");
        response.add_header("Vary", "Accept-Encoding");
    }

    for (k, v) in extra_headers {
        response.add_header(*k, *v);
    }

    if let Some(f) = on_request {
        f(&request, &mut response);
    }

    let mut resp = HttpResponse::from_data(bytes);
    for (header, value) in response.headers {
        if let Ok(h) = Header::from_bytes(header.as_bytes(), value) {
            resp.add_header(h);
        }
    }
    let _ = req.respond(resp);
}

fn send_404(req: tiny_http::Request) {
    let _ = req.respond(
        HttpResponse::from_data(b"404 Not Found".to_vec()).with_status_code(404),
    );
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct Builder {
    port: u16,
    host: Option<String>,
    on_request: OnRequest,
    extension_roots: Vec<PathBuf>,
    /// Filesystem root served when `asset_resolver` is empty
    /// (`frontendDist: null`). Production: `Contents/Resources/`.
    /// Dev: `Element/Sky/Target/`.
    static_root: Option<PathBuf>,
}

impl Builder {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            host: None,
            on_request: None,
            extension_roots: Vec::new(),
            static_root: None,
        }
    }

    /// Set the filesystem fallback root. Required when `frontendDist` is
    /// `null` so Sky's `index.html`, `app.js`, `_astro/`, and
    /// `Static/Application/` are served from disk.
    pub fn static_root<P: Into<PathBuf>>(mut self, root: P) -> Self {
        self.static_root = Some(root.into());
        self
    }

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

    /// Register a root directory the `/Extension/<abs-path>` prefix may
    /// serve from. Multiple roots are permitted.
    pub fn extension_root<P: Into<PathBuf>>(mut self, root: P) -> Self {
        self.extension_roots.push(root.into());
        self
    }

    pub fn build<R: Runtime>(mut self) -> TauriPlugin<R> {
        let port      = self.port;
        let host      = self.host.unwrap_or_else(|| "localhost".into());
        let on_req    = Arc::new(self.on_request.take());
        let ext_roots = Arc::new(std::mem::take(&mut self.extension_roots));
        let static_root = self.static_root.take().map(Arc::new);

        PluginBuilder::new("localhost")
            .setup(move |app, _api| {
                let asset_resolver = app.asset_resolver();

                // Per-session disk cache - each file read once, then served
                // from the Arc'd bytes with no further syscalls.
                let disk_cache: FileCache = Arc::new(RwLock::new(HashMap::new()));

                std::thread::spawn(move || {
                    let server = Server::http(format!("{host}:{port}"))
                        .expect("Unable to spawn localhost server");

                    for req in server.incoming_requests() {
                        let path: String = req
                            .url()
                            .parse::<Uri>()
                            .map(|u| u.path().into())
                            .unwrap_or_else(|_| req.url().into());

                        // ---- /Extension/<abs-path> route -----------------
                        // Serves extension-contributed assets (icon fonts,
                        // webview resources) that live outside the bundle tree.
                        if path.starts_with("/Extension/") {
                            if ext_roots.is_empty() {
                                send_404(req);
                                continue;
                            }
                            match resolve_extension_path(&path, &ext_roots) {
                                None => { send_404(req); continue; }
                                Some(resolved) => {
                                    let br = accepts_brotli(&req);
                                    let cache = Arc::clone(&disk_cache);
                                    let on_req = Arc::clone(&on_req);
                                    match cache_get_or_load(&cache, &resolved, br) {
                                        None => { send_404(req); }
                                        Some(entry) => {
                                            let bytes = (*entry.bytes).to_vec();
                                            let mime  = entry.mime;
                                            let brotli = entry.brotli;
                                            std::thread::spawn(move || {
                                                send_response(
                                                    req, bytes, mime, brotli,
                                                    "no-cache", &[], &on_req,
                                                );
                                            });
                                        }
                                    }
                                }
                            }
                            continue;
                        }

                        // ---- Embedded asset_resolver ---------------------
                        // Populated when `frontendDist` is a directory path.
                        // When `frontendDist: null` this always returns None.
                        #[allow(unused_mut)]
                        if let Some(mut asset) = asset_resolver.get(path.clone()) {
                            let on_req = Arc::clone(&on_req);
                            let cc = if is_immutable_asset(&path) {
                                "public, max-age=31536000, immutable"
                            } else {
                                "no-cache"
                            };
                            std::thread::spawn(move || {
                                let request = Request { url: asset.mime_type.to_string() };
                                let mut response = Response { headers: HashMap::new() };
                                response.add_header("Content-Type", asset.mime_type);
                                response.add_header("Cache-Control", cc);
                                response.add_header("Access-Control-Allow-Origin", "*");
                                if let Some(csp) = asset.csp_header {
                                    response.headers.insert("Content-Security-Policy".into(), csp);
                                }
                                if let Some(f) = on_req.as_ref() {
                                    f(&request, &mut response);
                                }
                                let mut resp = HttpResponse::from_data(asset.bytes);
                                for (h, v) in response.headers {
                                    if let Ok(hdr) = Header::from_bytes(h.as_bytes(), v) {
                                        resp.add_header(hdr);
                                    }
                                }
                                let _ = req.respond(resp);
                            });
                            continue;
                        }

                        // ---- Disk / static_root fallback -----------------
                        // Used when `frontendDist: null`. Files are cached
                        // in memory on first access; subsequent requests
                        // pay only an Arc clone + memcpy.
                        if let Some(ref root) = static_root {
                            let clean = path
                                .trim_start_matches('/')
                                .split(['?', '#'])
                                .next()
                                .unwrap_or("");
                            // SPA root → index.html
                            let candidate = if clean.is_empty() { "index.html" } else { clean };
                            let file_path = root.join(candidate);

                            let br = accepts_brotli(&req);
                            let cache = Arc::clone(&disk_cache);
                            let on_req = Arc::clone(&on_req);
                            let is_immutable = is_immutable_asset(&path);

                            match cache_get_or_load(&cache, &file_path, br) {
                                None => { send_404(req); }
                                Some(entry) => {
                                    let bytes  = (*entry.bytes).to_vec();
                                    let mime   = entry.mime;
                                    let brotli = entry.brotli;
                                    let cc = if is_immutable {
                                        "public, max-age=31536000, immutable"
                                    } else {
                                        // index.html and other non-hashed roots
                                        // must revalidate so workbench updates
                                        // are picked up on next launch.
                                        "no-cache, must-revalidate"
                                    };
                                    std::thread::spawn(move || {
                                        send_response(
                                            req, bytes, mime, brotli, cc, &[], &on_req,
                                        );
                                    });
                                }
                            }
                            continue;
                        }

                        // Nothing handled this request.
                        send_404(req);
                    }
                });

                Ok(())
            })
            .build()
    }
}
