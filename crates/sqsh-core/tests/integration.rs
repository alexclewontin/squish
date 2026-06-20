use std::sync::Arc;
use std::time::Duration;

use sqsh_core::proto::channel::*;
use sqsh_core::proto::message::*;
use sqsh_core::transport::framing::FramedBiStream;

/// Create a paired QUIC client and server endpoint on loopback for testing.
/// Returns (client_conn, server_conn, client_endpoint, server_endpoint).
/// The endpoints must be kept alive for the duration of the test.
async fn setup_quic_pair() -> (
    quinn::Connection,
    quinn::Connection,
    quinn::Endpoint,
    quinn::Endpoint,
) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut server_transport = quinn::TransportConfig::default();
    server_transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));
    server_config.transport_config(Arc::new(server_transport));

    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut client_transport = quinn::TransportConfig::default();
    client_transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    ));
    client_config.transport_config(Arc::new(client_transport));

    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

    let (client_conn, server_conn) =
        tokio::join!(async { client_connecting.await.unwrap() }, async {
            server_endpoint.accept().await.unwrap().await.unwrap()
        },);

    (client_conn, server_conn, client_endpoint, server_endpoint)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_stream_auth_handshake() {
    let (client_conn, server_conn, _ce, _se) = setup_quic_pair().await;
    // Keep connection refs alive so one side completing doesn't close the QUIC connection
    let (_cc, _sc) = (client_conn.clone(), server_conn.clone());

    tokio::join!(
        async move {
            let (send, recv) = client_conn.open_bi().await.unwrap();
            let mut stream = FramedBiStream::new(send, recv);

            stream
                .sender
                .send(&ControlMessage::ClientHello {
                    version: PROTOCOL_VERSION,
                    username: "testuser".into(),
                })
                .await
                .unwrap();

            let challenge: ControlMessage = stream.receiver.recv().await.unwrap();
            let nonce = match challenge {
                ControlMessage::AuthChallenge { nonce } => nonce,
                other => panic!("expected AuthChallenge, got {other:?}"),
            };
            assert_eq!(nonce.len(), 32);

            stream
                .sender
                .send(&ControlMessage::AuthResponse {
                    pubkey: vec![0xAA; 1952],
                    signature: vec![0xBB; 3293],
                })
                .await
                .unwrap();

            let result: ControlMessage = stream.receiver.recv().await.unwrap();
            match result {
                ControlMessage::AuthResult(AuthOutcome::Success) => {}
                other => panic!("expected AuthResult::Success, got {other:?}"),
            }
        },
        async move {
            let (send, recv) = server_conn.accept_bi().await.unwrap();
            let mut stream = FramedBiStream::new(send, recv);

            let hello: ControlMessage = stream.receiver.recv().await.unwrap();
            match hello {
                ControlMessage::ClientHello { version, username } => {
                    assert_eq!(version, PROTOCOL_VERSION);
                    assert_eq!(username, "testuser");
                }
                other => panic!("expected ClientHello, got {other:?}"),
            }

            stream
                .sender
                .send(&ControlMessage::AuthChallenge { nonce: [42u8; 32] })
                .await
                .unwrap();

            let response: ControlMessage = stream.receiver.recv().await.unwrap();
            match response {
                ControlMessage::AuthResponse { pubkey, signature } => {
                    assert_eq!(pubkey.len(), 1952);
                    assert_eq!(signature.len(), 3293);
                }
                other => panic!("expected AuthResponse, got {other:?}"),
            }

            stream
                .sender
                .send(&ControlMessage::AuthResult(AuthOutcome::Success))
                .await
                .unwrap();
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_open_and_data_exchange() {
    let (client_conn, server_conn, _ce, _se) = setup_quic_pair().await;
    let (_cc, _sc) = (client_conn.clone(), server_conn.clone());

    tokio::join!(
        async move {
            let (send, recv) = client_conn.open_bi().await.unwrap();
            let mut stream = FramedBiStream::new(send, recv);

            stream
                .sender
                .send(&ChannelMessage::Open {
                    channel_type: ChannelType::Session,
                    params: ChannelParams::Session,
                })
                .await
                .unwrap();

            let confirm: ChannelMessage = stream.receiver.recv().await.unwrap();
            match confirm {
                ChannelMessage::OpenConfirmation { max_packet_size } => {
                    assert_eq!(max_packet_size, 32768);
                }
                other => panic!("expected OpenConfirmation, got {other:?}"),
            }

            stream
                .sender
                .send(&ChannelMessage::Data {
                    data: b"hello server".to_vec(),
                })
                .await
                .unwrap();

            let reply: ChannelMessage = stream.receiver.recv().await.unwrap();
            match reply {
                ChannelMessage::Data { data } => {
                    assert_eq!(data, b"hello server");
                }
                other => panic!("expected Data echo, got {other:?}"),
            }

            stream.sender.send(&ChannelMessage::Close).await.unwrap();
        },
        async move {
            let (send, recv) = server_conn.accept_bi().await.unwrap();
            let mut stream = FramedBiStream::new(send, recv);

            let open: ChannelMessage = stream.receiver.recv().await.unwrap();
            match open {
                ChannelMessage::Open {
                    channel_type: ChannelType::Session,
                    ..
                } => {}
                other => panic!("expected Session open, got {other:?}"),
            }

            stream
                .sender
                .send(&ChannelMessage::OpenConfirmation {
                    max_packet_size: 32768,
                })
                .await
                .unwrap();

            let msg: ChannelMessage = stream.receiver.recv().await.unwrap();
            match msg {
                ChannelMessage::Data { data } => {
                    stream
                        .sender
                        .send(&ChannelMessage::Data { data })
                        .await
                        .unwrap();
                }
                other => panic!("expected Data, got {other:?}"),
            }

            let close: ChannelMessage = stream.receiver.recv().await.unwrap();
            assert!(matches!(close, ChannelMessage::Close));
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_channels_on_one_connection() {
    let (client_conn, server_conn, _ce, _se) = setup_quic_pair().await;

    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (send, recv) = server_conn.accept_bi().await.unwrap();
            tokio::spawn(async move {
                let mut stream = FramedBiStream::new(send, recv);

                let _open: ChannelMessage = stream.receiver.recv().await.unwrap();

                stream
                    .sender
                    .send(&ChannelMessage::OpenConfirmation {
                        max_packet_size: 32768,
                    })
                    .await
                    .unwrap();

                loop {
                    match stream.receiver.recv::<ChannelMessage>().await {
                        Ok(ChannelMessage::Data { data }) => {
                            stream
                                .sender
                                .send(&ChannelMessage::Data { data })
                                .await
                                .unwrap();
                        }
                        Ok(ChannelMessage::Close) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    for i in 1..=2 {
        let (send, recv) = client_conn.open_bi().await.unwrap();
        let mut stream = FramedBiStream::new(send, recv);
        stream
            .sender
            .send(&ChannelMessage::Open {
                channel_type: ChannelType::Session,
                params: ChannelParams::Session,
            })
            .await
            .unwrap();
        let _: ChannelMessage = stream.receiver.recv().await.unwrap();

        let payload = format!("channel-{i}").into_bytes();
        stream
            .sender
            .send(&ChannelMessage::Data {
                data: payload.clone(),
            })
            .await
            .unwrap();
        let reply: ChannelMessage = stream.receiver.recv().await.unwrap();
        match reply {
            ChannelMessage::Data { data } => assert_eq!(data, payload),
            other => panic!("expected Data, got {other:?}"),
        }
        stream.sender.send(&ChannelMessage::Close).await.unwrap();
    }

    server_task.await.unwrap();
}
