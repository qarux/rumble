use crate::protocol::parser::MUMBLE_PROTOCOL_VERSION;
use crate::server::client::{ClientWorker, Config as ClientConfig};
use crate::server::connection_worker::ConnectionWorker;
use crate::server::session_pool::SessionPool;
use crate::server::tcp_control_channel::TcpControlChannel;
use crate::server::udp_worker::{ServerInfo, UdpAudioChannel, UdpWorker};
use crate::storage::Storage;
use dashmap::DashMap;
use log::{error, info};
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

mod client;
mod connection_worker;
mod session_pool;
mod tcp_control_channel;
mod udp_worker;

pub struct Config {
    pub ip_address: IpAddr,
    pub port: u16,
    pub certificate: Certificate,
    pub private_key: PrivateKey,
    pub path_to_db_file: String,
}

pub struct Server {
    config: Config,
    rng: StdRng,
    storage: Arc<Storage>,
    clients: Arc<DashMap<SessionId, ClientWorker<TcpControlChannel, UdpAudioChannel>>>,
    session_pool: Arc<SessionPool>,
}
type SessionId = u32;

impl Server {
    pub fn new(config: Config) -> Self {
        let storage = Storage::open(&config.path_to_db_file);

        Server {
            config,
            rng: StdRng::from_entropy(),
            storage: Arc::new(storage),
            clients: Default::default(),
            session_pool: Arc::new(SessionPool::new()),
        }
    }

    pub async fn run(mut self) {
        let mut tls_config = ServerConfig::new(NoClientAuth::new());
        let result = tls_config.set_single_cert(
            vec![self.config.certificate.clone()],
            self.config.private_key.clone(),
        );
        if let Err(err) = result {
            error!("{}", err);
            panic!();
        }

        let socket_address = SocketAddr::new(self.config.ip_address, self.config.port);
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tcp_listener = match TcpListener::bind(socket_address).await {
            Ok(listener) => listener,
            Err(_) => {
                error!("Couldn't bind tcp socket to {}", socket_address);
                panic!();
            }
        };
        let udp_socket = match UdpSocket::bind(socket_address).await {
            Ok(socket) => socket,
            Err(_) => {
                error!("Couldn't bind udp socket to {}", socket_address);
                panic!();
            }
        };
        let server_info = ServerInfo {
            version: MUMBLE_PROTOCOL_VERSION.into(),
            connected_users: self.storage.watch_connected_count(),
            max_users: 10,
            max_bandwidth: 128000,
        };
        let udp_worker = Arc::new(UdpWorker::start(udp_socket, server_info).await);
        info!("Server listening on {}", socket_address);

        loop {
            let (tcp_stream, _) = match tcp_listener.accept().await {
                Ok(stream) => stream,
                Err(err) => {
                    info!("Tcp error: {}", err);
                    continue;
                }
            };
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    info!("Tls error: {}", err);
                    continue;
                }
            };
            let worker = ConnectionWorker::new(
                Arc::clone(&self.session_pool),
                Arc::clone(&self.storage),
                Arc::clone(&self.clients),
            );
            worker
                .start(
                    tls_stream,
                    self.create_client_config(),
                    Arc::clone(&udp_worker),
                )
                .await;
        }
    }

    fn create_client_config(&mut self) -> ClientConfig {
        let crypto_key = self.generate_key();
        let server_nonce = self.generate_key();
        let client_nonce = self.generate_key();
        ClientConfig {
            crypto_key,
            server_nonce,
            client_nonce,
            alpha_codec_version: -2147483637,
            beta_codec_version: -2147483632,
            prefer_alpha: true,
            opus_support: true,
            welcome_text: "Welcome".to_string(),
            max_bandwidth: 128000,
            max_users: 10,
            allow_html: true,
            max_message_length: 512,
            max_image_message_length: 100000,
            max_username_length: 64,
            min_compatible_version: 0x10200,
            server_password: None,
            pbkdf2_iterations: NonZeroU32::new(100_000).unwrap(),
        }
    }

    fn generate_key(&mut self) -> [u8; 16] {
        let mut buffer = [0; 16];
        self.rng.fill(&mut buffer);
        buffer
    }
}
