use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::proto::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::xfer::Protocol;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::ServerConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use time::{Duration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};

mod structs;
use structs::config::{CaConfig, Config};

// ── Config ──────────────────────────────────────────────────────────────────

// ── CA helpers ──────────────────────────────────────────────────────────────

/// Load or generate a CA key-pair. If cert/key files exist on disk they are
/// loaded; otherwise a fresh self-signed CA is created and persisted to the
/// configured paths (defaulting to `ca.crt` / `ca.key`).
fn load_or_create_ca(ca_cfg: Option<&CaConfig>) -> (rcgen::Certificate, KeyPair) {
    let cert_path = ca_cfg.and_then(|c| c.cert.as_deref()).unwrap_or("ca.crt");
    let key_path = ca_cfg.and_then(|c| c.key.as_deref()).unwrap_or("ca.key");

    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        info!("[ca] Loading existing CA from {cert_path} / {key_path}");

        let key_pem = fs::read_to_string(key_path).expect("read CA key");
        let cert_pem = fs::read_to_string(cert_path).expect("read CA cert");

        let key_pair = KeyPair::from_pem(&key_pem).expect("parse CA key");
        let params = CertificateParams::from_ca_cert_pem(&cert_pem).expect("parse CA cert");
        let cert = params.self_signed(&key_pair).expect("re-sign CA cert");

        (cert, key_pair)
    } else {
        info!("[ca] Generating new CA → {cert_path} / {key_path}");

        let (name, organization, country, state, locality) = ca_cfg
            .map(|c| {
                (
                    c.common_name.as_deref().unwrap_or("Mallory CA"),
                    c.organization.as_deref().unwrap_or("Mallory"),
                    c.country.as_deref().unwrap_or("US"),
                    c.state.as_deref().unwrap_or("California"),
                    c.locality.as_deref().unwrap_or("San Francisco"),
                )
            })
            .unwrap_or(("Mallory CA", "Mallory", "US", "California", "San Francisco"));

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn.push(DnType::OrganizationName, organization);
        dn.push(DnType::CountryName, country);
        dn.push(DnType::StateOrProvinceName, state);
        dn.push(DnType::LocalityName, locality);

        params.distinguished_name = dn;

        // Valid for 10 years, starting yesterday to avoid clock skew issues.
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // RSA-2048 because it's widely supported.
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("generate CA key");
        let cert = params.self_signed(&key_pair).expect("self-sign CA");

        fs::write(cert_path, cert.pem()).expect("write CA cert");
        fs::write(key_path, key_pair.serialize_pem()).expect("write CA key");

        (cert, key_pair)
    }
}

/// Issue a TLS leaf certificate for the given list of domain names, signed by
/// the provided CA.
fn issue_cert(
    domains: &[String],
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> (Vec<u8>, Vec<u8>) {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &domains[0]);
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    params.subject_alt_names = domains
        .iter()
        .map(|d| SanType::DnsName(d.clone().try_into().unwrap()))
        .collect();

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("generate leaf key");
    let leaf_cert = params
        .signed_by(&leaf_key, ca_cert, ca_key)
        .expect("sign leaf cert");

    let cert_der = leaf_cert.der().to_vec();
    let key_der = leaf_key.serialize_der();

    (cert_der, key_der)
}

// ── Routing state ───────────────────────────────────────────────────────────

/// Maps a domain name → upstream target URL (e.g. "http://localhost:8080").
type RouteMap = HashMap<String, String>;

/// Maps a domain name → custom DNS server address to use for resolving the target.
type DnsMap = HashMap<String, String>;

// ── Insecure upstream TLS client ────────────────────────────────────────────

/// A certificate verifier that accepts any server certificate (including
/// self-signed). This is intentional – Mallory is a debugging/dev proxy.
#[derive(Debug)]
struct DangerousVerifier;

impl ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build an HTTP+HTTPS client that skips TLS certificate verification on
/// upstream connections.
fn build_upstream_client() -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
> {
    let tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
        .with_no_client_auth();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_cfg)
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
}

// ── Proxy handler ───────────────────────────────────────────────────────────

async fn handle(
    req: Request<Incoming>,
    routes: Arc<RouteMap>,
    dns_map: Arc<DnsMap>,
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Determine the host from the request.
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(String::from));

    let Some(host) = host else {
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("missing Host header")))
            .unwrap());
    };

    let Some(target_base) = routes.get(&host) else {
        error!(host = %host, "no route for host");
        return Ok(Response::builder()
            .status(502)
            .body(Full::new(Bytes::from(format!("no upstream for {host}"))))
            .unwrap());
    };

    // Build the upstream URI, resolving via custom DNS if configured.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let upstream_uri = match resolve_target(target_base, &host, &dns_map).await {
        Ok(resolved) => format!("{resolved}{path_and_query}")
            .parse::<hyper::Uri>()
            .expect("valid upstream URI"),
        Err(e) => {
            error!(host = %host, error = %e, "DNS resolution failed");
            return Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("DNS resolution error: {e}"))))
                .unwrap());
        }
    };

    info!("{host}{path_and_query} → {upstream_uri}");

    // Build a forwarded request.
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = req.into_body().collect().await?.to_bytes();

    // Reconstruct the request with the new URI and same method/headers/body.
    let mut upstream_req = Request::builder().method(method).uri(&upstream_uri);
    for (k, v) in &headers {
        upstream_req = upstream_req.header(k, v);
    }
    let upstream_req = upstream_req
        .body(Full::new(body_bytes.clone()))
        .expect("build upstream request");

    // Send it.
    match client.request(upstream_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body_bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();

            Ok(Response::from_parts(parts, Full::new(body_bytes)))
        }
        Err(e) => {
            if e.is_connect() {
                error!(
                    "[proxy] target {}:{} is not accepting connections: {e}",
                    upstream_uri.host().unwrap_or("<no host>"),
                    upstream_uri.port_u16().unwrap_or(80)
                );

                return Ok(Response::builder()
                    .status(hyper::StatusCode::GATEWAY_TIMEOUT)
                    .body(Full::new(Bytes::from(format!(
                        "upstream connection error: {e}"
                    ))))
                    .unwrap());
            }

            error!("[proxy] error forwarding request: {e}");

            Ok(Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("upstream error: {e}"))))
                .unwrap())
        }
    }
}

// ── DNS resolution ──────────────────────────────────────────────────────────

/// Loopback hosts that should be exempt from custom DNS resolution.
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// If a custom DNS server is configured for this domain, resolve the target's
/// hostname through it and return a rewritten base URL with the resolved IP.
/// Otherwise return the original target unchanged.
async fn resolve_target(
    target_base: &str,
    host: &str,
    dns_map: &DnsMap,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let Some(dns_server) = dns_map.get(host) else {
        return Ok(target_base.to_string());
    };

    let target_uri: hyper::Uri = target_base.parse()?;
    let target_host = target_uri.host().ok_or("target has no host")?;

    // If the target is already an IP, skip resolution.
    if target_host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(target_base.to_string());
    }

    // If the target is a loopback address, skip resolution.
    if LOOPBACK_HOSTS.contains(&target_host) {
        return Ok(target_base.to_string());
    }

    let dns_addr: SocketAddr = if dns_server.contains(':') {
        dns_server.parse()?
    } else {
        format!("{dns_server}:53").parse()?
    };

    let ns = NameServerConfig::new(dns_addr, Protocol::Udp);
    let mut resolver_cfg = ResolverConfig::new();
    resolver_cfg.add_name_server(ns);

    let resolver = TokioResolver::builder_with_config(
        resolver_cfg,
        GenericConnector::new(TokioRuntimeProvider::new()),
    )
    .build();

    let lookup = resolver.lookup_ip(target_host).await?;
    let ip = lookup
        .iter()
        .next()
        .ok_or_else(|| format!("no DNS records for {target_host} via {dns_server}"))?;

    let port = target_uri
        .port_u16()
        .unwrap_or(match target_uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
    let scheme = target_uri.scheme_str().unwrap_or("http");

    let resolved = format!("{scheme}://{ip}:{port}");
    info!(
        host = %host,
        dns = %dns_server,
        resolved = %resolved,
        "resolved target via custom DNS"
    );

    Ok(resolved)
}

// ── TLS config ──────────────────────────────────────────────────────────────

fn build_tls_config(
    cert_ders: &[Vec<u8>],
    key_ders: &[Vec<u8>],
    ca_cert: &rcgen::Certificate,
) -> ServerConfig {
    use rustls::crypto::ring::sign::any_supported_type;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;

    struct Resolver {
        certified_keys: Vec<Arc<CertifiedKey>>,
        /// domain → index into certified_keys
        sni_map: HashMap<String, usize>,
    }

    impl std::fmt::Debug for Resolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Resolver")
                .field("sni_map", &self.sni_map)
                .finish()
        }
    }

    impl ResolvesServerCert for Resolver {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            let sni = client_hello.server_name()?;
            let idx = self.sni_map.get(sni)?;
            Some(self.certified_keys[*idx].clone())
        }
    }

    let ca_der = CertificateDer::from(ca_cert.der().to_vec());

    let mut certified_keys = Vec::new();
    let mut sni_map: HashMap<String, usize> = HashMap::new();

    for (i, (cert_der, key_der)) in cert_ders.iter().zip(key_ders.iter()).enumerate() {
        let cert_chain = vec![CertificateDer::from(cert_der.clone()), ca_der.clone()];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone()));
        let signing_key = any_supported_type(&private_key).expect("parse signing key");
        let ck = Arc::new(CertifiedKey::new(cert_chain, signing_key));
        certified_keys.push(ck);

        // Parse the cert to extract SANs for the sni_map.
        let parsed = x509_parser::parse_x509_certificate(cert_der).expect("parse leaf cert");
        let (_, parsed_cert) = parsed;
        if let Ok(Some(san_ext)) = parsed_cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    sni_map.insert(dns.to_string(), i);
                }
            }
        }
    }

    let resolver = Resolver {
        certified_keys,
        sni_map,
    };

    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();

    ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver))
}

// ── Main ────────────────────────────────────────────────────────────────────

fn init_tracing() {
    use tracing_subscriber::prelude::*;

    let level: LevelFilter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(LevelFilter::INFO);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .pretty()
        .with_filter(level);

    tracing_subscriber::registry().with(fmt_layer).init();
}

fn init_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;

    Ok(config)
}

#[tokio::main]
async fn main() {
    init_tracing();

    let config = init_config("proxy.toml").unwrap_or_else(|e| {
        error!("failed to read config: {}", e);
        Config::default()
    });

    let listen_addr: SocketAddr = config
        .listen
        .as_deref()
        .unwrap_or(structs::config::DEFAULT_LISTEN)
        .parse()
        .expect("valid listen address");

    // 2. Load / generate CA
    let (ca_cert, ca_key) = load_or_create_ca(config.ca.as_ref());

    // 3. Issue leaf certs for every proxy entry and build route map + dns map
    let mut routes: RouteMap = HashMap::new();
    let mut dns_map: DnsMap = HashMap::new();
    let mut all_cert_ders: Vec<Vec<u8>> = Vec::new();
    let mut all_key_ders: Vec<Vec<u8>> = Vec::new();

    for (name, entry) in &config.proxies {
        info!(
            name = name,
            domains = ?entry.domains,
            target = %entry.target,
            dns = ?entry.dns,
            "configuring proxy"
        );

        let (cert_der, key_der) = issue_cert(&entry.domains, &ca_cert, &ca_key);
        all_cert_ders.push(cert_der);
        all_key_ders.push(key_der);

        for domain in &entry.domains {
            routes.insert(domain.clone(), entry.target.clone());
            if let Some(ref dns) = entry.dns {
                dns_map.insert(domain.clone(), dns.clone());
            }
        }
    }

    // 4. Build a rustls ServerConfig with a custom cert resolver so we can
    //    serve the right cert per-SNI.
    let tls_config = build_tls_config(&all_cert_ders, &all_key_ders, &ca_cert);
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let routes = Arc::new(routes);
    let dns_map = Arc::new(dns_map);
    let client = build_upstream_client();

    // 5. Bind & serve
    let listener = TcpListener::bind(listen_addr).await.expect("bind listener");
    info!("listening on {}", listen_addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("[accept] {e}");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let routes = routes.clone();
        let dns_map = dns_map.clone();
        let client = client.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!("[tls] {peer}: {e}");
                    return;
                }
            };

            let io = hyper_util::rt::TokioIo::new(tls_stream);

            if let Err(e) = server_http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let routes = routes.clone();
                        let dns_map = dns_map.clone();
                        let client = client.clone();
                        handle(req, routes, dns_map, client)
                    }),
                )
                .await
            {
                error!("[http] {peer}: {e}");
            }
        });
    }
}
