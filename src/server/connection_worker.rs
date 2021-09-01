use crate::crypto::Ocb2Aes128Crypto;
use crate::protocol::parser::{AudioData, TextMessage, UserState};
use crate::server::client::{Client, ClientEvent, Config, Error, ServerEvent};
use crate::server::session_pool::{SessionId, SessionPool};
use crate::server::tcp_control_channel::TcpControlChannel;
use crate::server::udp_audio_channel::{UdpAudioChannel, UdpWorker};
use crate::storage::Storage;
use dashmap::DashMap;
use log::info;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio_rustls::server::TlsStream;

pub struct ConnectionWorker {
    session_id: SessionId,
    session_pool: Arc<SessionPool>,
    storage: Arc<Storage>,
    clients: Arc<DashMap<SessionId, Client<TcpControlChannel, UdpAudioChannel>>>,
}

impl ConnectionWorker {
    pub fn new(
        session_pool: Arc<SessionPool>,
        storage: Arc<Storage>,
        clients: Arc<DashMap<SessionId, Client<TcpControlChannel, UdpAudioChannel>>>,
    ) -> Self {
        ConnectionWorker {
            session_id: session_pool.pop(),
            session_pool,
            storage,
            clients,
        }
    }

    pub async fn start(self, stream: TlsStream<TcpStream>, config: Config, worker: Arc<UdpWorker>) {
        tokio::spawn(async move {
            let address = stream.get_ref().0.peer_addr().unwrap();
            if self
                .process_new_connection(stream, config, worker)
                .await
                .is_err()
            {
                info!("Failed to establish connection {}", address)
            }
        });
    }

    async fn process_new_connection(
        self,
        stream: TlsStream<TcpStream>,
        config: Config,
        worker: Arc<UdpWorker>,
    ) -> Result<(), Error> {
        let address = stream.get_ref().0.peer_addr().unwrap();
        let crypto =
            Ocb2Aes128Crypto::new(config.crypto_key, config.server_nonce, config.client_nonce);
        let control_channel = TcpControlChannel::new(stream);
        let (client, event_receiver) = Client::setup_connection(
            self.session_id,
            Arc::clone(&self.storage),
            control_channel,
            config,
        )
        .await?;
        info!("Connection established successfully {}", address);

        let session_id = self.session_id;
        for client in self.clients.iter() {
            client.send_event(ServerEvent::Connected(session_id)).await;
        }
        self.clients.insert(session_id, client);

        let clients = Arc::clone(&self.clients);
        let task = tokio::spawn(async move {
            let audio_channel = worker.new_audio_channel(address.ip(), crypto).await;
            if let Some(client) = clients.get_mut(&session_id).as_deref_mut() {
                client.set_audio_channel(audio_channel).await;
            }
        });

        self.event_loop(event_receiver).await;
        task.abort();
        info!("Disconnected {}", address);

        Ok(())
    }

    async fn event_loop(&self, mut event_receiver: Receiver<ClientEvent>) {
        loop {
            let message = event_receiver.recv().await.unwrap();
            match message {
                ClientEvent::Disconnected => {
                    self.clients.remove(&self.session_id);
                    self.broadcast_disconnect().await;
                    self.session_pool.push(self.session_id);
                    return;
                }
                ClientEvent::Talking(audio_data) => {
                    self.broadcast_audio(audio_data).await;
                }
                ClientEvent::StateChanged(state) => {
                    self.broadcast_state_change(state).await;
                }
                ClientEvent::TextMessage(message) => {
                    self.broadcast_message(message).await;
                }
            }
        }
    }

    async fn broadcast_disconnect(&self) {
        for client in self.clients.iter() {
            client
                .send_event(ServerEvent::Disconnected(self.session_id))
                .await;
        }
    }

    async fn broadcast_audio(&self, audio: AudioData) {
        for client in self
            .clients
            .iter()
            .filter(|el| *el.key() != self.session_id)
        {
            client.send_event(ServerEvent::Talking(audio.clone())).await;
        }
    }

    async fn broadcast_state_change(&self, state: UserState) {
        for client in self.clients.iter() {
            client
                .send_event(ServerEvent::StateChanged(state.clone()))
                .await;
        }
    }

    async fn broadcast_message(&self, message: TextMessage) {
        for client in self.clients.iter().filter(|client| {
            self.session_id != *client.key()
                && (message.targets.is_empty() || message.targets.contains(client.key()))
        }) {
            client
                .send_event(ServerEvent::TextMessage(message.clone()))
                .await;
        }
    }
}
