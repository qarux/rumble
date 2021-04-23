use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig, NoClientAuth};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use crate::protocol::{MumblePacketStream};

pub struct Config {
    pub ip_address: IpAddr,
    pub port: u16,
    pub certificate: Certificate,
    pub private_key: PrivateKey,
}

pub async fn run(config: Config) -> std::io::Result<()> {
    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    tls_config.set_single_cert(vec![config.certificate], config.private_key)
        .expect("Invalid private key");

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(
        SocketAddr::new(config.ip_address, config.port)
    ).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await;
            if let Ok(stream) = stream {
                process(MumblePacketStream::new(stream)).await;
            }
        });
    }
}

async fn process(stream: MumblePacketStream<TlsStream<TcpStream>>) {}
