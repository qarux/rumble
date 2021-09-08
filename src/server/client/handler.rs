use crate::protocol::connection::{AudioChannel, ControlChannel, Error};
use crate::protocol::parser::{
    AudioData, AudioPacket, Authenticate, ChannelState, CodecVersion, ControlMessage, CryptSetup,
    ParsingError, Ping, ServerConfig, ServerSync, SessionId, TextMessage, UdpTunnel, UserRemove,
    UserState, Version, MUMBLE_PROTOCOL_VERSION,
};
use crate::server::client::client_worker::{ClientEvent, ServerEvent};
use crate::storage::{Guest, SessionData, Storage};
use log::error;
use ring::pbkdf2;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Sender;

static PBKDF2_ALGORITHM: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

type Key = [u8; 16];
type Nonce = [u8; 16];

pub struct Handler<C: ControlChannel, A: AudioChannel> {
    storage: Arc<Storage>,
    control_channel: Arc<C>,
    audio_channel: Option<Arc<A>>,
    event_sender: Sender<ClientEvent>,
    config: Config,
    session_id: u32,
    crypto_resyncs: u32,
}

pub struct Config {
    pub crypto_key: Key,
    pub server_nonce: Nonce,
    pub client_nonce: Nonce,
    pub alpha_codec_version: i32,
    pub beta_codec_version: i32,
    pub prefer_alpha: bool,
    pub opus_support: bool,
    pub welcome_text: String,
    pub max_bandwidth: u32,
    pub max_users: u32,
    pub allow_html: bool,
    pub max_message_length: u32,
    pub max_image_message_length: u32,
    pub max_username_length: u32,
    pub min_compatible_version: u32,
    pub server_password: Option<String>,
    pub pbkdf2_iterations: NonZeroU32,
}

pub enum HandlerError {
    IO(std::io::Error),
    PacketParsing(ParsingError),
    EventReceiverClosed,
}

pub enum ConnectionSetupError {
    IO(std::io::Error),
    PacketParsing(ParsingError),
    Reject(Reject),
    WrongPacket,
}

pub enum Reject {
    InvalidUsername,
    UsernameInUse,
    _WrongVersion,
    WrongUserPassword,
    _WrongServerPassword,
    _NoCertificate,
}

impl<C: ControlChannel, A: AudioChannel> Handler<C, A> {
    pub fn new(
        storage: Arc<Storage>,
        control_channel: Arc<C>,
        event_sender: Sender<ClientEvent>,
        session_id: u32,
        config: Config,
    ) -> Self {
        Handler {
            storage,
            control_channel,
            audio_channel: None,
            event_sender,
            session_id,
            crypto_resyncs: 0,
            config,
        }
    }
}

impl<C: ControlChannel, A: AudioChannel> Handler<C, A> {
    pub fn set_audio_channel(&mut self, channel: Arc<A>) {
        self.audio_channel = Some(channel);
    }

    pub async fn handle_new_connection(&self) -> Result<(), ConnectionSetupError> {
        match self.control_channel.receive().await? {
            ControlMessage::Version(_) => {
                // TODO check version
            }
            _ => return Err(ConnectionSetupError::WrongPacket),
        };
        // TODO
        let auth = match self.control_channel.receive().await? {
            ControlMessage::Authenticate(auth) => auth,
            _ => return Err(ConnectionSetupError::WrongPacket),
        };
        self.authenticate(auth).await?;

        let version = Version {
            version: Some(MUMBLE_PROTOCOL_VERSION),
        };
        let crypt_setup = CryptSetup {
            key: Some(Vec::from(self.config.crypto_key)),
            client_nonce: Some(Vec::from(self.config.client_nonce)),
            server_nonce: Some(Vec::from(self.config.server_nonce)),
        };
        let channel_states = self
            .storage
            .get_channels()
            .into_iter()
            .map(|channel| ChannelState {
                id: Some(channel.id),
                name: Some(channel.name),
            });
        let user_states: Vec<UserState> = self.get_user_states();
        let codec_version = CodecVersion {
            celt_alpha_version: self.config.alpha_codec_version,
            celt_beta_version: self.config.beta_codec_version,
            prefer_alpha: self.config.prefer_alpha,
            opus_support: self.config.opus_support,
        };
        let server_sync = ServerSync {
            user_session_id: SessionId::from(self.session_id),
            max_bandwidth: self.config.max_bandwidth,
            welcome_text: self.config.welcome_text.clone(),
        };
        let server_config = ServerConfig {
            max_users: self.config.max_users,
            max_message_length: self.config.max_message_length,
        };

        self.control_channel.send(version).await?;
        self.control_channel.send(crypt_setup).await?;
        for channel_state in channel_states {
            self.control_channel.send(channel_state).await?;
        }
        for user_state in user_states.into_iter() {
            self.control_channel.send(user_state).await?;
        }
        self.control_channel.send(codec_version).await?;
        self.control_channel.send(server_sync).await?;
        self.control_channel.send(server_config).await?;

        Ok(())
    }

    pub async fn handle_server_event(&self, event: ServerEvent) -> Result<(), HandlerError> {
        match event {
            ServerEvent::Connected(session_id) => self.new_user_connected(session_id).await?,
            ServerEvent::StateChanged(state) => self.user_state_changed(state).await?,
            ServerEvent::Talking(audio_data) => self.user_talking(audio_data).await?,
            ServerEvent::Disconnected(session_id) => self.user_disconnected(session_id).await?,
            ServerEvent::TextMessage(message) => self.user_text_message(message).await?,
        }

        Ok(())
    }

    pub async fn handle_message(&self, packet: ControlMessage) -> Result<(), HandlerError> {
        match packet {
            ControlMessage::Ping(ping) => self.control_ping(ping).await?,
            ControlMessage::TextMessage(message) => self.text_message(message).await?,
            ControlMessage::UserState(state) => self.user_state(state).await?,
            ControlMessage::UdpTunnel(tunnel) => self.tunnel(tunnel).await?,
            _ => error!("unimplemented!"),
        }
        Ok(())
    }

    pub async fn handle_audio_packet(&self, packet: AudioPacket) -> Result<(), HandlerError> {
        match packet {
            AudioPacket::Ping(_) => {
                if let Some(channel) = self.audio_channel.as_ref() {
                    channel.send(packet).await?;
                }
            }
            AudioPacket::AudioData(mut audio_data) => {
                audio_data.session_id = Some(SessionId::from(self.session_id));
                self.event_sender
                    .send(ClientEvent::Talking(audio_data))
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn self_disconnected(&self) -> Result<(), HandlerError> {
        self.storage.remove_by_session_id(self.session_id);
        self.event_sender.send(ClientEvent::Disconnected).await?;
        Ok(())
    }

    // Control packets
    async fn control_ping(&self, incoming: Ping) -> Result<(), HandlerError> {
        let mut ping = Ping {
            timestamp: incoming.timestamp,
            good: None,
            late: None,
            lost: None,
            resyncs: None,
        };
        if let Some(channel) = self.audio_channel.as_ref() {
            let stats = channel.get_stats();
            ping.good = Some(stats.good);
            ping.late = Some(stats.late);
            ping.lost = Some(stats.lost);
            ping.resyncs = Some(self.crypto_resyncs);
        }

        self.control_channel.send(ping).await?;
        Ok(())
    }

    async fn text_message(&self, mut message: TextMessage) -> Result<(), HandlerError> {
        if self.config.max_message_length < message.message.len() as u32 {
            // TODO send the permission denied message
            return Ok(());
        }
        if message.sender.is_none() {
            message.sender = Some(SessionId::from(self.session_id));
        }
        self.event_sender
            .send(ClientEvent::TextMessage(message))
            .await?;
        Ok(())
    }

    async fn user_state(&self, mut state: UserState) -> Result<(), HandlerError> {
        if state.session_id.is_none() {
            state.session_id = Some(SessionId::from(self.session_id));
        }

        let session_data = SessionData {
            muted_by_admin: state.muted_by_admin.unwrap_or_default(),
            deafened_by_admin: state.deafened_by_admin.unwrap_or_default(),
            suppressed: false,
            self_mute: state.self_mute.unwrap_or_default(),
            self_deaf: state.self_deaf.unwrap_or_default(),
            priority_speaker: false,
            recording: false,
        };
        self.storage
            .update_session_data(self.session_id, session_data);
        self.event_sender
            .send(ClientEvent::StateChanged(state))
            .await?;

        Ok(())
    }

    async fn tunnel(&self, tunnel: UdpTunnel) -> Result<(), HandlerError> {
        match tunnel.audio_packet {
            AudioPacket::Ping(_) => {
                self.control_channel
                    .send(UdpTunnel::from(tunnel.audio_packet))
                    .await?;
            }
            AudioPacket::AudioData(mut audio_data) => {
                audio_data.session_id = Some(SessionId::from(self.session_id));
                self.event_sender
                    .send(ClientEvent::Talking(audio_data))
                    .await?;
            }
        }

        Ok(())
    }

    // Server events
    async fn new_user_connected(&self, session_id: u32) -> Result<(), HandlerError> {
        let id = Some(SessionId::from(session_id));
        if let Some(user) = self.storage.get_connected_user(session_id) {
            self.control_channel
                .send(UserState {
                    session_id: id,
                    name: Some(user.username),
                    channel_id: Some(user.channel_id),
                    ..Default::default()
                })
                .await?;
        } else if let Some(guest) = self.storage.get_guest(session_id) {
            self.control_channel
                .send(UserState {
                    session_id: id,
                    name: Some(guest.username),
                    channel_id: Some(guest.channel_id),
                    ..Default::default()
                })
                .await?;
        }

        Ok(())
    }

    async fn user_state_changed(&self, state: UserState) -> Result<(), HandlerError> {
        self.control_channel.send(state).await?;
        Ok(())
    }

    async fn user_talking(&self, audio_data: AudioData) -> Result<(), HandlerError> {
        if let Some(data) = self.storage.get_session_data(self.session_id) {
            if data.self_deaf || data.deafened_by_admin {
                return Ok(());
            }
        }

        let audio_packet = AudioPacket::AudioData(audio_data);
        if let Some(channel) = self.audio_channel.as_ref() {
            channel.send(audio_packet).await?;
        } else {
            self.control_channel
                .send(UdpTunnel::from(audio_packet))
                .await?;
        }

        Ok(())
    }

    async fn user_disconnected(&self, session_id: u32) -> Result<(), HandlerError> {
        let user_remove = UserRemove {
            session_id: session_id.into(),
        };
        Ok(self.control_channel.send(user_remove).await?)
    }

    async fn user_text_message(&self, message: TextMessage) -> Result<(), HandlerError> {
        self.control_channel.send(message).await?;
        Ok(())
    }

    // Utils
    async fn authenticate(&self, auth: Authenticate) -> Result<(), ConnectionSetupError> {
        let username = match auth.username {
            Some(username) => username,
            None => return Err(ConnectionSetupError::Reject(Reject::InvalidUsername)),
        };
        if !validate_username(&username, self.config.max_username_length as usize) {
            return Err(ConnectionSetupError::Reject(Reject::InvalidUsername));
        }

        if self.storage.username_in_connected(&username) {
            return Err(ConnectionSetupError::Reject(Reject::UsernameInUse));
        }

        let user = match self.storage.get_user_by_username(username.clone()) {
            Some(user) => user,
            None => {
                self.storage
                    .add_guest(Guest::new(username, self.session_id, 0));
                return Ok(());
            }
        };

        if let (Some(stored_password_hash), Some(iterations), Some(salt)) = (
            &user.password_hash,
            user.pbkdf2_iterations,
            &user.password_salt,
        ) {
            let password = match auth.password {
                Some(password) => password,
                None => return Err(ConnectionSetupError::Reject(Reject::WrongUserPassword)),
            };
            pbkdf2::verify(
                PBKDF2_ALGORITHM,
                iterations,
                salt,
                password.as_bytes(),
                stored_password_hash,
            )
            .map_err(|_| ConnectionSetupError::Reject(Reject::WrongUserPassword))?;
        }

        self.storage.add_connected_user(user, self.session_id);

        Ok(())
    }

    fn get_user_states(&self) -> Vec<UserState> {
        let guests = self.storage.get_guests();
        let users = self.storage.get_connected_users();
        let mut states = Vec::with_capacity(guests.len() + users.len());
        for guest in guests {
            let state = UserState {
                session_id: Some(SessionId::from(guest.session_id)),
                name: Some(guest.username),
                channel_id: Some(guest.channel_id),
                ..Default::default()
            };
            states.push(state);
        }

        for (session_id, user) in users {
            let state = UserState {
                session_id: Some(SessionId::from(session_id)),
                name: Some(user.username),
                channel_id: Some(user.channel_id),
                ..Default::default()
            };
            states.push(state);
        }
        states
    }
}

fn validate_username(username: &str, max_username_length: usize) -> bool {
    !username.is_empty()
        && username.trim().len() == username.len()
        && username.len() <= max_username_length
}

impl From<Error> for HandlerError {
    fn from(err: crate::protocol::connection::Error) -> Self {
        match err {
            Error::IO(err) => HandlerError::IO(err),
            Error::Parsing(err) => HandlerError::PacketParsing(err),
        }
    }
}

impl From<Error> for ConnectionSetupError {
    fn from(err: Error) -> Self {
        match err {
            Error::IO(err) => ConnectionSetupError::IO(err),
            Error::Parsing(err) => ConnectionSetupError::PacketParsing(err),
        }
    }
}

impl From<SendError<ClientEvent>> for HandlerError {
    fn from(_: SendError<ClientEvent>) -> Self {
        HandlerError::EventReceiverClosed
    }
}
