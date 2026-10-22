use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use http::header::ALT_SVC;
use http::{HeaderValue, Request, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, Incoming, ServerConfig, TransportConfig, VarInt};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;
use tracing::debug;

use crate::tls::{ReloadableCertResolver, TlsError};

const MAX_CONCURRENT_BIDI_STREAMS: u32 = 256;
const MAX_CONCURRENT_CONNECTIONS: usize = 512;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const ALT_SVC_MAX_AGE_SECS: u32 = 86_400;

pub fn build_quic_server_config(
    resolver: Arc<ReloadableCertResolver>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto =
        QuicServerConfig::try_from(crypto).map_err(|e| TlsError::Config(e.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS));
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .expect("idle timeout fits in varint"),
    ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

pub fn alt_svc_header(port: u16) -> HeaderValue {
    HeaderValue::from_str(&format!("h3=\":{port}\"; ma={ALT_SVC_MAX_AGE_SECS}"))
        .expect("alt-svc header value is valid ascii")
}

pub fn with_alt_svc(app: Router, port: u16) -> Router {
    let value = alt_svc_header(port);
    app.layer(axum::middleware::map_response(
        move |mut response: Response<Body>| {
            let value = value.clone();
            async move {
                if response.status() != StatusCode::SWITCHING_PROTOCOLS {
                    response.headers_mut().insert(ALT_SVC, value);
                }
                response
            }
        },
    ))
}

pub fn with_host_from_authority(app: Router) -> Router {
    app.layer(axum::middleware::map_request(
        |mut request: Request<Body>| async move {
            let authority = request
                .uri()
                .authority()
                .map(|a| HeaderValue::from_str(a.as_str()));
            match (
                request.headers().contains_key(http::header::HOST),
                authority,
            ) {
                (false, Some(Ok(value))) => {
                    request.headers_mut().insert(http::header::HOST, value);
                    request
                }
                _ => request,
            }
        },
    ))
}

pub async fn serve_http3(endpoint: Endpoint, app: Router, shutdown: CancellationToken) {
    let tracker = TaskTracker::new();
    let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(permit) = conn_limiter.clone().try_acquire_owned() else {
                    debug!(
                        peer = %incoming.remote_address(),
                        max = MAX_CONCURRENT_CONNECTIONS,
                        "refusing h3 connection: limit reached"
                    );
                    incoming.refuse();
                    continue;
                };
                let app = app.clone();
                let conn_shutdown = shutdown.clone();
                let conn_tracker = tracker.clone();
                tracker.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve_connection(incoming, app, conn_shutdown, conn_tracker).await {
                        debug!("h3 connection ended: {e}");
                    }
                });
            }
        }
    }
    tracker.close();
    if tokio::time::timeout(SHUTDOWN_GRACE, tracker.wait())
        .await
        .is_err()
    {
        debug!("h3 connections did not drain within grace, closing");
    }
    endpoint.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
}

async fn serve_connection(
    incoming: Incoming,
    app: Router,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = incoming.await?;
    let remote = conn.remote_address();
    let mut h3_conn = h3::server::builder()
        .max_field_section_size(64 * 1024)
        .build::<_, Bytes>(h3_quinn::Connection::new(conn))
        .await?;

    let mut draining = false;
    loop {
        tokio::select! {
            _ = shutdown.cancelled(), if !draining => {
                draining = true;
                let _ = h3_conn.shutdown(0).await;
            }
            resolved = h3_conn.accept() => match resolved {
                Ok(Some(resolver)) => {
                    let app = app.clone();
                    tracker.spawn(async move {
                        if let Err(e) = serve_request(resolver, app, remote).await {
                            debug!(peer = %remote, "h3 request failed: {e}");
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    debug!(peer = %remote, "h3 accept error: {e}");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    app: Router,
    remote: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (req, stream) = resolver.resolve_request().await?;
    let (mut send, recv) = stream.split();

    let (mut parts, ()) = req.into_parts();
    parts.extensions.insert(ConnectInfo(remote));
    let request = Request::from_parts(parts, request_body(recv));

    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    };

    let (parts, body) = response.into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;

    let mut data = body.into_data_stream();
    while let Some(chunk) = data.next().await {
        match chunk {
            Ok(bytes) if bytes.has_remaining() => send.send_data(bytes).await?,
            Ok(_) => {}
            Err(e) => {
                debug!(peer = %remote, "h3 response body error: {e}");
                send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                return Ok(());
            }
        }
    }
    send.finish().await?;
    Ok(())
}

struct RecvGuard {
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    ended: bool,
}

impl Drop for RecvGuard {
    fn drop(&mut self) {
        if !self.ended {
            self.stream.stop_sending(h3::error::Code::H3_NO_ERROR);
        }
    }
}

fn request_body(recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>) -> Body {
    let guard = RecvGuard {
        stream: recv,
        ended: false,
    };
    let stream = futures_util::stream::unfold(Some(guard), |state| async move {
        let mut guard = state?;
        match guard.stream.recv_data().await {
            Ok(Some(mut buf)) => {
                let bytes = buf.copy_to_bytes(buf.remaining());
                Some((Ok::<Bytes, std::io::Error>(bytes), Some(guard)))
            }
            Ok(None) => {
                guard.ended = true;
                None
            }
            Err(e) => {
                guard.ended = true;
                Some((Err(std::io::Error::other(e.to_string())), None))
            }
        }
    });
    Body::from_stream(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };

    fn self_signed_resolver() -> Arc<ReloadableCertResolver> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der).unwrap();
        let certified = rustls::sign::CertifiedKey::new(vec![cert_der], signing_key);
        Arc::new(ReloadableCertResolver::new(certified))
    }

    #[derive(Debug)]
    struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn client_endpoint() -> Endpoint {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        endpoint
    }

    #[tokio::test]
    async fn h3_get_roundtrips_through_router() {
        let app = Router::new().route("/", get(|| async { "ok" }));
        let server_config = build_quic_server_config(self_signed_resolver()).unwrap();
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        tokio::spawn(serve_http3(server, app, shutdown.clone()));

        let client = client_endpoint();
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let req = Request::get("https://localhost/").body(()).unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), 200);

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&bytes);
        }
        assert_eq!(body.as_slice(), b"ok");

        shutdown.cancel();
        drive.abort();
    }

    #[test]
    fn alt_svc_header_advertises_h3() {
        assert_eq!(
            alt_svc_header(443).to_str().unwrap(),
            "h3=\":443\"; ma=86400"
        );
    }

    #[tokio::test]
    async fn alt_svc_added_to_responses_except_switching_protocols() {
        let app = with_alt_svc(
            Router::new().route("/ok", get(|| async { "ok" })).route(
                "/upgrade",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .body(Body::empty())
                        .unwrap()
                }),
            ),
            443,
        );

        let normal = app
            .clone()
            .oneshot(Request::get("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            normal.headers().get(ALT_SVC).and_then(|v| v.to_str().ok()),
            Some("h3=\":443\"; ma=86400")
        );

        let upgrade = app
            .oneshot(Request::get("/upgrade").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            upgrade.headers().get(ALT_SVC).is_none(),
            "101 responses must not carry Alt-Svc"
        );
    }

    fn make_cert(dns: &str) -> (rustls::sign::CertifiedKey, CertificateDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec![dns.to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der).unwrap();
        let certified = rustls::sign::CertifiedKey::new(vec![cert_der.clone()], signing_key);
        (certified, cert_der)
    }

    #[derive(Debug)]
    struct RecordingVerifier {
        provider: Arc<rustls::crypto::CryptoProvider>,
        seen: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            *self.seen.lock().unwrap() = end_entity.as_ref().to_vec();
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    async fn observe_server_cert(addr: SocketAddr) -> Vec<u8> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let verifier = Arc::new(RecordingVerifier {
            provider: provider.clone(),
            seen: seen.clone(),
        });
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        seen.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn quic_handshake_observes_reloaded_certificate() {
        let (cert_a, der_a) = make_cert("localhost");
        let (cert_b, der_b) = make_cert("localhost");
        assert_ne!(der_a, der_b, "test must use two distinct certs");

        let resolver = Arc::new(ReloadableCertResolver::new(cert_a));
        let server_config = build_quic_server_config(resolver.clone()).unwrap();
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let app = Router::new().route("/", get(|| async { "ok" }));
        tokio::spawn(serve_http3(server, app, shutdown.clone()));

        let before = observe_server_cert(addr).await;
        assert_eq!(
            before.as_slice(),
            der_a.as_ref(),
            "first handshake must present the original cert"
        );

        resolver.store(cert_b);

        let after = observe_server_cert(addr).await;
        assert_eq!(
            after.as_slice(),
            der_b.as_ref(),
            "handshake after reload must present the new cert"
        );
        assert_ne!(before, after, "reload must change the presented cert");

        shutdown.cancel();
    }

    #[tokio::test]
    async fn h3_requests_carry_remote_addr_connect_info() {
        let app = Router::new().route(
            "/",
            get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { addr.to_string() }),
        );
        let server_config = build_quic_server_config(self_signed_resolver()).unwrap();
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        tokio::spawn(serve_http3(server, app, shutdown.clone()));

        let client = client_endpoint();
        let client_port = client.local_addr().unwrap().port();
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let req = Request::get("https://localhost/").body(()).unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&bytes);
        }
        let reported: SocketAddr = String::from_utf8(body).unwrap().parse().unwrap();
        assert!(reported.ip().is_loopback());
        assert_eq!(
            reported.port(),
            client_port,
            "handlers must see the QUIC remote address via ConnectInfo"
        );

        shutdown.cancel();
        drive.abort();
    }

    #[tokio::test]
    async fn host_header_filled_from_authority() {
        let app = with_host_from_authority(Router::new().route(
            "/",
            get(|headers: http::HeaderMap| async move {
                headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
                    .unwrap_or_default()
            }),
        ));
        let server_config = build_quic_server_config(self_signed_resolver()).unwrap();
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        tokio::spawn(serve_http3(server, app, shutdown.clone()));

        let client = client_endpoint();
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let req = Request::get("https://localhost/").body(()).unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&bytes);
        }
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "localhost",
            "handlers must see the authority as the Host header"
        );

        shutdown.cancel();
        drive.abort();
    }

    #[tokio::test]
    async fn h3_body_error_resets_stream_instead_of_truncating() {
        let app = Router::new().route(
            "/",
            get(|| async {
                Body::from_stream(futures_util::stream::iter(vec![
                    Ok::<Bytes, std::io::Error>(Bytes::from_static(b"partial")),
                    Err(std::io::Error::other("body source failed")),
                ]))
            }),
        );
        let server_config = build_quic_server_config(self_signed_resolver()).unwrap();
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        tokio::spawn(serve_http3(server, app, shutdown.clone()));

        let client = client_endpoint();
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let req = Request::get("https://localhost/").body(()).unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let outcome = async {
            stream.recv_response().await?;
            let mut body = Vec::new();
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        body.extend_from_slice(&bytes);
                    }
                    Ok(None) => return Ok(body),
                    Err(e) => return Err(e),
                }
            }
        }
        .await;
        assert!(
            outcome.is_err(),
            "a mid-body error must reset the stream, not end the body cleanly after {} bytes",
            outcome.map(|b| b.len()).unwrap_or(0)
        );

        shutdown.cancel();
        drive.abort();
    }
}
