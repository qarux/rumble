use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsStream};

use crate::client::{Client, ClientEvent, ServerEvent};
use crate::connection::{AudioChannel, ControlChannel};
use crate::crypto::Ocb2Aes128Crypto;
use crate::db::Db;
use crate::protocol::AudioData;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};

use tokio::sync::mpsc::{Receiver, Sender};

use log::{error, info, warn};

pub const MAX_UDP_DATAGRAM_SIZE: usize = 1024;

pub struct Config {
    pub ip_address: IpAddr,
    pub port: u16,
    pub certificate: Certificate,
    pub private_key: PrivateKey,
    pub path_to_db_file: String,
}

pub struct Server {
    config: Config,
    db: Arc<Db>,
    clients: RwLock<HashMap<SessionId, Client>>,
    waiting_for_audio_channel: Mutex<Vec<(SessionId, IpAddr, Ocb2Aes128Crypto)>>,
    address_to_channel: RwLock<HashMap<SocketAddr, Sender<Vec<u8>>>>,
}

type SessionId = u32;

impl Server {
    pub fn new(config: Config) -> Arc<Self> {
        let path_to_db_file = config.path_to_db_file.clone();

        Arc::new(Server {
            config,
            clients: RwLock::new(HashMap::new()),
            db: Arc::new(Db::open(&path_to_db_file)),
            waiting_for_audio_channel: Mutex::new(vec![]),
            address_to_channel: RwLock::new(HashMap::new()),
        })
    }

    pub async fn run(self: Arc<Self>) {
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
        info!("Server listening on {}", socket_address);

        Arc::clone(&self).run_udp_task(udp_socket).await;
        Arc::clone(&self)
            .listen_for_new_connections(tcp_listener, tls_acceptor)
            .await;
    }

    async fn run_udp_task(self: Arc<Self>, socket: UdpSocket) {
        let socket = Arc::new(socket);
        tokio::spawn(async move {
            let mut buf = [0; MAX_UDP_DATAGRAM_SIZE];
            loop {
                if let Ok((len, socket_address)) = socket.recv_from(&mut buf).await {
                    if !Arc::clone(&self)
                        .send_to_audio_channel(&buf[..len], &socket_address)
                        .await
                    {
                        // TODO Move to a separate task
                        Arc::clone(&self)
                            .match_address_to_channel(
                                &buf[..len],
                                socket_address,
                                Arc::clone(&socket),
                            )
                            .await;
                    }
                }
            }
        });
    }

    async fn send_to_audio_channel(self: &Arc<Self>, buf: &[u8], address: &SocketAddr) -> bool {
        let connected = self.address_to_channel.read().await;
        if let Some(sender) = connected.get(address) {
            sender.send(Vec::from(buf)).await;
            return true;
        }

        false
    }

    async fn match_address_to_channel(
        self: &Arc<Self>,
        buf: &[u8],
        address: SocketAddr,
        udp_socket: Arc<UdpSocket>,
    ) {
        let mut waiting = self.waiting_for_audio_channel.lock().await;
        let index = match waiting
            .iter_mut()
            .position(|(_, ip, crypto)| &address.ip() == ip && crypto.decrypt(buf).is_ok())
        {
            Some(index) => index,
            None => return,
        };
        let (session_id, _, crypto) = waiting.remove(index);
        drop(waiting);

        let (sender, receiver) = mpsc::channel(1);
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(&session_id) {
            let audio_channel = AudioChannel::new(receiver, udp_socket, crypto, address);
            client.set_audio_channel(audio_channel).await;
        }
        drop(clients);

        let mut address_to_channel = self.address_to_channel.write().await;
        address_to_channel.insert(address, sender);
    }

    async fn listen_for_new_connections(
        self: Arc<Self>,
        listener: TcpListener,
        acceptor: TlsAcceptor,
    ) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            let server = Arc::clone(&self);

            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await;
                if let Ok(stream) = stream {
                    server.process_new_connection(TlsStream::from(stream)).await;
                }
            });
        }
    }

    async fn process_new_connection(self: Arc<Self>, stream: TlsStream<TcpStream>) {
        let address = stream.get_ref().0.peer_addr().unwrap();
        info!("New connection: {}", address);

        let (session_id, mut responder) = match self.new_client(stream).await {
            Ok(id) => {
                info!("Connection established successfully {}", address);
                id
            }
            Err(_) => {
                info!("Failed to establish connection {}", address);
                return;
            }
        };

        loop {
            let message = match responder.recv().await {
                Some(msg) => msg,
                None => {
                    warn!("Connection closed unexpectedly");
                    return;
                }
            };

            match message {
                ClientEvent::Disconnected => {
                    self.client_disconnected(session_id).await;
                    info!("Disconnected {}", address);
                    return;
                }
                ClientEvent::Talking(audio_data) => {
                    self.client_talking(session_id, audio_data).await;
                }
            }
        }
    }

    async fn client_disconnected(&self, session_id: SessionId) {
        let mut clients = self.clients.write().await;
        clients.remove(&session_id);
        for client in clients.values() {
            client
                .send_event(ServerEvent::UserDisconnected(session_id))
                .await;
        }
        drop(clients);

        //TODO optimize
        let mut waiting = self.waiting_for_audio_channel.lock().await;
        if let Some(index) = waiting.iter().position(|(id, _, _)| session_id == *id) {
            waiting.remove(index);
        } else {
            drop(waiting);

            let mut address_to_channel = self.address_to_channel.write().await;
            if let Some(key) = address_to_channel
                .keys()
                .find(|key| address_to_channel.get(key).unwrap().is_closed())
                .cloned()
            {
                address_to_channel.remove(&key);
            }
        }
    }

    async fn client_talking(&self, session_id: SessionId, audio: AudioData) {
        let clients = self.clients.read().await;
        for client in clients
            .values()
            .filter(|client| client.session_id != session_id)
        {
            client
                .send_event(ServerEvent::UserTalking(audio.clone()))
                .await;
        }
    }

    async fn new_client(
        self: &Arc<Self>,
        stream: TlsStream<TcpStream>,
    ) -> Result<(SessionId, Receiver<ClientEvent>), crate::client::Error> {
        let ip = stream.get_ref().0.peer_addr().unwrap().ip();
        let config = self.create_client_config();
        let crypto =
            Ocb2Aes128Crypto::new(config.crypto_key, config.server_nonce, config.client_nonce);
        let (client, receiver) =
            Client::establish_connection(Arc::clone(&self.db), ControlChannel::new(stream), config)
                .await?;

        let session_id = client.session_id;
        let mut clients = self.clients.write().await;
        for client in clients.values() {
            client
                .send_event(ServerEvent::UserConnected(session_id))
                .await;
        }
        clients.insert(session_id, client);
        drop(clients);

        let mut waiting = self.waiting_for_audio_channel.lock().await;
        waiting.push((session_id, ip, crypto));
        drop(waiting);

        Ok((session_id, receiver))
    }

    fn create_client_config(&self) -> crate::client::Config {
        let crypto_key = self.generate_key();
        let server_nonce = self.generate_key();
        let client_nonce = self.generate_key();
        crate::client::Config {
            crypto_key,
            server_nonce,
            client_nonce,
            alpha_codec_version: 0,
            beta_codec_version: 0,
            prefer_alpha: true,
            opus_support: true,
            welcome_text: "Welcome".to_string(),
            max_bandwidth: 128000,
            max_users: 10,
            allow_html: true,
            max_message_length: 512,
            max_image_message_length: 100000,
        }
    }

    fn generate_key(&self) -> [u8; 16] {
        let mut buffer = [0; 16];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut buffer);
        buffer
    }
}
