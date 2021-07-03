use std::sync::Arc;

use log::error;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;

use crate::client::Error::StreamError;
use crate::connection::{AudioChannel, ControlChannel};
use crate::db::{Db, User};
use crate::proto::mumble::{
    ChannelState, CodecVersion, CryptSetup, Ping, ServerConfig, ServerSync, UserRemove, UserState,
    Version,
};
use crate::protocol::{AudioData, AudioPacket, MumblePacket, MUMBLE_PROTOCOL_VERSION};
use std::sync::atomic::Ordering;

pub struct Client {
    pub session_id: u32,
    inner_event_sender: Sender<InnerEvent>,
    handler_task: JoinHandle<()>,
    control_channel_task: JoinHandle<()>,
    audio_channel_task: Option<JoinHandle<()>>,
}

pub struct Config {
    pub crypto_key: [u8; 16],
    pub server_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
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
}

pub enum ClientEvent {
    Talking(AudioData),
    Disconnected,
}

pub enum ServerEvent {
    UserConnected(u32),
    UserDisconnected(u32),
    UserTalking(AudioData),
}

pub enum Error {
    AuthenticationError,
    StreamError,
    WrongPacket,
}

struct Handler {
    db: Arc<Db>,
    control_channel: Arc<ControlChannel>,
    audio_channel: Option<Arc<AudioChannel>>,
    client_event_sender: Sender<ClientEvent>,
    session_id: u32,
    crypto_resyncs: u32,
}

enum InnerEvent {
    ServerEvent(ServerEvent),
    ControlPacket(MumblePacket),
    AudioPacket(AudioPacket),
    AudioChannel(Arc<AudioChannel>),
    SelfDisconnected,
}

impl Client {
    pub async fn establish_connection(
        db: Arc<Db>,
        control_channel: ControlChannel,
        config: Config,
    ) -> Result<(Self, Receiver<ClientEvent>), Error> {
        match control_channel.receive().await? {
            MumblePacket::Version(version) => version,
            _ => return Err(Error::WrongPacket),
        };
        let mut auth = match control_channel.receive().await? {
            MumblePacket::Authenticate(auth) => auth,
            _ => return Err(Error::WrongPacket),
        };
        if !auth.has_username() {
            return Err(Error::AuthenticationError);
        }
        let session_id = db.add_new_user(auth.take_username()).await;

        let version = {
            let mut version = Version::new();
            version.set_version(MUMBLE_PROTOCOL_VERSION);
            MumblePacket::Version(version)
        };
        let crypt_setup = {
            let key = config.crypto_key;
            let server_nonce = config.server_nonce;
            let client_nonce = config.client_nonce;
            let mut crypt_setup = CryptSetup::new();
            crypt_setup.set_key(Vec::from(key));
            crypt_setup.set_server_nonce(Vec::from(server_nonce));
            crypt_setup.set_client_nonce(Vec::from(client_nonce));
            MumblePacket::CryptSetup(crypt_setup)
        };
        let codec_version = {
            let mut codec_version = CodecVersion::new();
            codec_version.set_alpha(config.alpha_codec_version);
            codec_version.set_beta(config.beta_codec_version);
            codec_version.set_prefer_alpha(config.prefer_alpha);
            codec_version.set_opus(config.opus_support);
            MumblePacket::CodecVersion(codec_version)
        };
        let channel_states: Vec<MumblePacket> = {
            db.get_channels()
                .await
                .into_iter()
                .map(|channel| {
                    let mut channel_state = ChannelState::new();
                    channel_state.set_channel_id(channel.id);
                    channel_state.set_name(channel.name);
                    MumblePacket::ChannelState(channel_state)
                })
                .collect()
        };
        let user_states: Vec<MumblePacket> = {
            db.get_connected_users()
                .await
                .into_iter()
                .map(|user| {
                    let mut user_state = UserState::new();
                    user_state.set_name(user.username);
                    user_state.set_session(user.session_id);
                    user_state.set_channel_id(user.channel_id);
                    MumblePacket::UserState(user_state)
                })
                .collect()
        };
        let server_sync = {
            let mut server_sync = ServerSync::new();
            server_sync.set_session(session_id);
            server_sync.set_welcome_text(config.welcome_text);
            server_sync.set_max_bandwidth(config.max_bandwidth);
            MumblePacket::ServerSync(server_sync)
        };
        let server_config = {
            let mut server_config = ServerConfig::new();
            server_config.set_max_users(config.max_users);
            server_config.set_allow_html(config.allow_html);
            server_config.set_message_length(config.max_message_length);
            server_config.set_image_message_length(config.max_image_message_length);
            MumblePacket::ServerConfig(server_config)
        };

        control_channel.send(version).await?;
        control_channel.send(crypt_setup).await?;
        control_channel.send(codec_version).await?;
        control_channel.send_multiple(channel_states).await?;
        control_channel.send_multiple(user_states).await?;
        control_channel.send(server_sync).await?;
        control_channel.send(server_config).await?;

        let (client, response_receiver) = Client::new(control_channel, db, session_id).await;
        Ok((client, response_receiver))
    }

    pub async fn set_audio_channel(&mut self, audio_channel: AudioChannel) {
        let audio_channel = Arc::new(audio_channel);
        let channel = Arc::clone(&audio_channel);
        let sender = self.inner_event_sender.clone();
        self.audio_channel_task = Some(tokio::spawn(async move {
            loop {
                match channel.receive().await {
                    Ok(packet) => {
                        sender.send(InnerEvent::AudioPacket(packet)).await;
                    }
                    Err(_) => break,
                }
            }
        }));

        self.inner_event_sender
            .send(InnerEvent::AudioChannel(audio_channel))
            .await;
    }

    pub async fn send_event(&self, event: ServerEvent) {
        self.inner_event_sender
            .send(InnerEvent::ServerEvent(event))
            .await;
    }

    async fn new(
        control_channel: ControlChannel,
        db: Arc<Db>,
        session_id: u32,
    ) -> (Self, Receiver<ClientEvent>) {
        let (inner_event_sender, inner_event_receiver) = mpsc::channel(1);
        let (client_event_sender, response_receiver) = mpsc::channel(1);
        let control_channel = Arc::new(control_channel);
        let handler = Handler {
            db,
            control_channel: Arc::clone(&control_channel),
            audio_channel: None,
            client_event_sender,
            session_id,
            crypto_resyncs: 0,
        };
        let client = Client {
            session_id,
            inner_event_sender: inner_event_sender.clone(),
            handler_task: Self::run_handler_task(handler, inner_event_receiver).await,
            control_channel_task: Self::run_control_channel_task(
                control_channel,
                inner_event_sender,
            )
            .await,
            audio_channel_task: None,
        };

        return (client, response_receiver);
    }

    async fn run_handler_task(
        mut handler: Handler,
        mut inner_event_receiver: Receiver<InnerEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let message = match inner_event_receiver.recv().await {
                    Some(msg) => msg,
                    None => {
                        error!("Handler task closed unexpectedly");
                        break;
                    }
                };

                let result = match message {
                    InnerEvent::ServerEvent(event) => handler.handle_server_event(event).await,
                    InnerEvent::ControlPacket(packet) => {
                        handler.handle_control_packet(packet).await
                    }
                    InnerEvent::AudioPacket(audio) => handler.handle_audio_packet(audio).await,
                    InnerEvent::AudioChannel(channel) => {
                        handler.audio_channel = Some(channel);
                        Ok(())
                    }
                    InnerEvent::SelfDisconnected => {
                        handler.self_disconnected().await;
                        break;
                    }
                };

                if let Err(_) = result {
                    // TODO
                    error!("Handler task error");
                }
            }
        })
    }

    async fn run_control_channel_task(
        control_channel: Arc<ControlChannel>,
        sender: Sender<InnerEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match control_channel.receive().await {
                    Ok(packet) => sender.send(InnerEvent::ControlPacket(packet)).await,
                    Err(_) => {
                        // TODO
                        sender.send(InnerEvent::SelfDisconnected).await;
                        return;
                    }
                };
            }
        })
    }
}

impl Handler {
    async fn handle_server_event(&self, message: ServerEvent) -> Result<(), Error> {
        match message {
            ServerEvent::UserConnected(session_id) => self.new_user_connected(session_id).await?,
            ServerEvent::UserDisconnected(session_id) => self.user_disconnected(session_id).await?,
            ServerEvent::UserTalking(audio_data) => self.user_talking(audio_data).await?,
        }

        Ok(())
    }

    async fn handle_control_packet(&self, packet: MumblePacket) -> Result<(), Error> {
        match packet {
            MumblePacket::Ping(ping) => self.handle_control_channel_ping(ping).await?,
            MumblePacket::UdpTunnel(packet) => self.handle_tunnel(packet).await?,
            MumblePacket::ChannelRemove(_) => error!("ChannelRemove unimplemented!"),
            MumblePacket::ChannelState(_) => error!("ChannelState unimplemented!"),
            MumblePacket::UserRemove(_) => error!("UserRemove unimplemented!"),
            MumblePacket::UserState(_) => error!("UserState unimplemented!"),
            MumblePacket::BanList(_) => error!("BanList unimplemented!"),
            MumblePacket::TextMessage(_) => error!("TextMessage unimplemented!"),
            MumblePacket::QueryUsers(_) => error!("TextMessage unimplemented!"),
            MumblePacket::CryptSetup(_) => error!("CryptSetup unimplemented!"),
            MumblePacket::ContextAction(_) => error!("ContextAction unimplemented!"),
            MumblePacket::UserList(_) => error!("UserList unimplemented!"),
            MumblePacket::VoiceTarget(_) => error!("VoiceTarget unimplemented!"),
            MumblePacket::PermissionQuery(_) => error!("PermissionQuery unimplemented!"),
            MumblePacket::UserStats(_) => error!("UserStats unimplemented!"),
            MumblePacket::RequestBlob(_) => error!("RequestBlob unimplemented!"),
            MumblePacket::Acl(_) => error!("Acl unimplemented!"),
            // The rest is only sent by the server
            _ => return Err(Error::WrongPacket),
        }
        Ok(())
    }

    async fn handle_control_channel_ping(&self, ping: Ping) -> Result<(), Error> {
        let timestamp = ping.get_timestamp();
        let mut ping = Ping::new();
        if ping.has_timestamp() {
            ping.set_timestamp(timestamp);
        }
        if let Some(channel) = self.audio_channel.as_ref() {
            ping.set_good(channel.good.load(Ordering::Acquire));
            ping.set_late(channel.late.load(Ordering::Acquire));
            ping.set_lost(channel.lost.load(Ordering::Acquire));
            ping.set_resync(self.crypto_resyncs);
        }

        self.control_channel.send(MumblePacket::Ping(ping)).await?;
        Ok(())
    }

    async fn handle_tunnel(&self, packet: AudioPacket) -> Result<(), Error> {
        match packet {
            AudioPacket::Ping(_) => {
                self.control_channel
                    .send(MumblePacket::UdpTunnel(packet))
                    .await?;
            }
            AudioPacket::AudioData(mut audio_data) => {
                audio_data.session_id = Some(self.session_id);
                self.client_event_sender
                    .send(ClientEvent::Talking(audio_data))
                    .await;
            }
        }

        Ok(())
    }

    async fn handle_audio_packet(&self, packet: AudioPacket) -> Result<(), Error> {
        match packet {
            AudioPacket::Ping(_) => {
                self.audio_channel.as_ref().unwrap().send(packet).await;
            }
            AudioPacket::AudioData(mut audio_data) => {
                audio_data.session_id = Some(self.session_id);
                self.client_event_sender
                    .send(ClientEvent::Talking(audio_data))
                    .await;
            }
        }

        Ok(())
    }

    async fn new_user_connected(&self, session_id: u32) -> Result<(), Error> {
        if let Some(user) = self.db.get_user_by_session_id(session_id).await {
            self.control_channel.send(MumblePacket::from(user)).await?;
        }
        Ok(())
    }

    async fn user_disconnected(&self, session_id: u32) -> Result<(), Error> {
        let mut user_remove = UserRemove::new();
        user_remove.set_session(session_id);
        Ok(self
            .control_channel
            .send(MumblePacket::UserRemove(user_remove))
            .await?)
    }

    async fn self_disconnected(&self) {
        self.db.remove_connected_user(self.session_id).await;
        self.client_event_sender
            .send(ClientEvent::Disconnected)
            .await;
    }

    async fn user_talking(&self, audio_data: AudioData) -> Result<(), Error> {
        let audio_packet = AudioPacket::AudioData(audio_data);
        if let Some(channel) = self.audio_channel.as_ref() {
            channel.send(audio_packet).await?;
        } else {
            self.control_channel
                .send(MumblePacket::UdpTunnel(audio_packet))
                .await;
        }

        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.handler_task.abort();
        self.control_channel_task.abort();
        if let Some(audio_task) = self.audio_channel_task.as_ref() {
            audio_task.abort();
        }
    }
}

impl From<User> for UserState {
    fn from(user: User) -> Self {
        let mut user_state = UserState::new();
        if let Some(id) = user.id {
            user_state.set_user_id(id)
        }
        user_state.set_name(user.username);
        user_state.set_channel_id(user.channel_id);
        user_state.set_session(user.session_id);
        user_state
    }
}

impl From<User> for MumblePacket {
    fn from(user: User) -> Self {
        MumblePacket::UserState(UserState::from(user))
    }
}

impl From<crate::protocol::Error> for Error {
    fn from(_: crate::protocol::Error) -> Self {
        StreamError
    }
}

impl From<crate::connection::Error> for Error {
    fn from(_: crate::connection::Error) -> Self {
        StreamError
    }
}
