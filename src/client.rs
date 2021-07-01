use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use log::{info, error};

use crate::client::Error::StreamError;
use crate::connection::{AudioChannel, AudioChannelSender, ControlChannel, ControlChannelSender};
use crate::db::{Db, User};
use crate::proto::mumble::{
    ChannelState, CodecVersion, CryptSetup, Ping, ServerConfig, ServerSync, UserRemove, UserState,
    Version,
};
use crate::protocol::{AudioData, AudioPacket, MumblePacket, MUMBLE_PROTOCOL_VERSION};

pub struct Client {
    pub session_id: u32,
    inner_sender: Sender<InnerMessage>,
    handler_task: JoinHandle<()>,
    packet_task: JoinHandle<()>,
    audio_task: Option<JoinHandle<()>>,
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

pub enum Message {
    UserConnected(u32),
    UserDisconnected(u32),
    UserTalking(AudioData),
}

pub enum ResponseMessage {
    Disconnected,
    Talking(AudioData),
}

pub enum Error {
    AuthenticationError,
    StreamError,
    WrongPacket,
}

struct Handler {
    session_id: u32,
    db: Arc<Db>,
    control_channel_sender: ControlChannelSender,
    audio_channel_sender: Option<AudioChannelSender>,
    response_sender: Sender<ResponseMessage>,
    is_audio_tunneling: bool,
}

enum InnerMessage {
    Message(Message),
    Packet(Box<MumblePacket>),
    Audio(AudioPacket),
    AudioChannel(AudioChannelSender),
    SelfDisconnected,
}

type Responder = Receiver<ResponseMessage>;

impl Client {
    pub async fn establish_connection(
        db: Arc<Db>,
        mut control_channel: ControlChannel,
        config: Config,
    ) -> Result<(Self, Responder), Error> {
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
        for channel_state in channel_states {
            control_channel.send(channel_state).await?;
        }
        for user_state in user_states {
            control_channel.send(user_state).await?;
        }
        control_channel.send(server_sync).await?;
        control_channel.send(server_config).await?;

        let (client, response_receiver) = Client::new(control_channel, db, session_id).await;
        Ok((client, response_receiver))
    }

    pub async fn set_audio_channel(&mut self, audio_channel: AudioChannel) {
        let (mut receiver, sender) = audio_channel.split();
        let inner_sender = self.inner_sender.clone();
        self.audio_task = Some(tokio::spawn(async move {
            loop {
                match receiver.receive().await {
                    Ok(packet) => {
                        inner_sender.try_send(InnerMessage::Audio(packet));
                    }
                    Err(_) => return,
                }
            }
        }));

        self.inner_sender
            .send(InnerMessage::AudioChannel(sender))
            .await;
    }

    pub async fn send_message(&self, message: Message) {
        match message {
            Message::UserTalking(_) => {
                self.inner_sender.try_send(InnerMessage::Message(message));
            }
            _ => {
                self.inner_sender.send(InnerMessage::Message(message)).await;
            }
        }
    }

    async fn new(
        control_channel: ControlChannel,
        db: Arc<Db>,
        session_id: u32,
    ) -> (Client, Responder) {
        let (inner_sender, mut inner_receiver) = mpsc::channel(2);
        let (response_sender, response_receiver) = mpsc::channel(2);

        let (mut control_channel_receiver, control_channel_sender) = control_channel.split();
        let handler_task = tokio::spawn(async move {
            let mut handler = Handler {
                session_id,
                db,
                control_channel_sender,
                audio_channel_sender: None,
                response_sender,
                is_audio_tunneling: false,
            };
            loop {
                let message = match inner_receiver.recv().await {
                    Some(msg) => msg,
                    None => return,
                };

                match message {
                    InnerMessage::Message(msg) => {
                        let result = handler.handle_message(msg).await;
                        if result.is_err() {
                            handler.self_disconnected().await;
                            return;
                        }
                    }
                    InnerMessage::Packet(packet) => {
                        let result = handler.handle_mumble_packet(*packet).await;
                        if result.is_err() {
                            handler.self_disconnected().await;
                            return;
                        }
                    }
                    InnerMessage::SelfDisconnected => {
                        handler.self_disconnected().await;
                        return;
                    }
                    InnerMessage::Audio(audio) => {
                        let result = handler.handle_audio_packet(audio).await;
                        if result.is_err() {
                            handler.self_disconnected().await;
                            return;
                        }
                    }
                    InnerMessage::AudioChannel(sender) => {
                        handler.audio_channel_sender = Some(sender)
                    }
                }
            }
        });

        let sender = inner_sender.clone();
        let packet_task = tokio::spawn(async move {
            loop {
                match control_channel_receiver.receive().await {
                    Ok(packet) => sender.send(InnerMessage::Packet(Box::from(packet))).await,
                    Err(_) => {
                        sender.send(InnerMessage::SelfDisconnected).await;
                        return;
                    }
                };
            }
        });

        return (
            Client {
                session_id,
                inner_sender,
                handler_task,
                packet_task,
                audio_task: None,
            },
            response_receiver,
        );
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.handler_task.abort();
        self.packet_task.abort();
        if let Some(audio_task) = self.audio_task.as_ref() {
            audio_task.abort();
        }
    }
}

impl Handler {
    async fn handle_mumble_packet(&mut self, packet: MumblePacket) -> Result<(), Error> {
        match packet {
            MumblePacket::Ping(ping) => {
                if ping.has_timestamp() {
                    let mut ping = Ping::new();
                    ping.set_timestamp(ping.get_timestamp());
                    self.control_channel_sender
                        .send(MumblePacket::Ping(ping))
                        .await?;
                }
            }
            MumblePacket::UdpTunnel(voice) => match voice {
                AudioPacket::Ping(_) => {
                    self.control_channel_sender
                        .send(MumblePacket::UdpTunnel(voice))
                        .await?;
                }
                AudioPacket::AudioData(mut audio_data) => {
                    audio_data.session_id = Some(self.session_id);
                    self.response_sender
                        .try_send(ResponseMessage::Talking(audio_data));
                }
            },
            MumblePacket::ChannelRemove(_) => error!("ChannelRemove unimplemented!"),
            MumblePacket::ChannelState(_) => error!("ChannelState unimplemented!"),
            MumblePacket::UserRemove(_) => error!("UserRemove unimplemented!"),
            MumblePacket::UserState(_) => error!("UserState unimplemented!"),
            MumblePacket::BanList(_) => error!("BanList unimplemented!"),
            MumblePacket::TextMessage(_) => error!("TextMessage unimplemented!"),
            MumblePacket::QueryUsers(_) => error!("TextMessage unimplemented!"),
            MumblePacket::CryptSetup(_) => error!("CryptSetup unimplemented!"),
            MumblePacket::ContextActionModify(_) => error!("ContextActionModify unimplemented!"),
            MumblePacket::ContextAction(_) => error!("ContextAction unimplemented!"),
            MumblePacket::UserList(_) => error!("UserList unimplemented!"),
            MumblePacket::VoiceTarget(_) => error!("VoiceTarget unimplemented!"),
            MumblePacket::PermissionQuery(_) => error!("PermissionQuery unimplemented!"),
            MumblePacket::UserStats(_) => error!("UserStats unimplemented!"),
            MumblePacket::RequestBlob(_) => error!("RequestBlob unimplemented!"),
            // The rest is only sent by the server
            _ => return Err(Error::WrongPacket),
        }
        Ok(())
    }

    async fn handle_message(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::UserConnected(session_id) => self.new_user_connected(session_id).await?,
            Message::UserDisconnected(session_id) => self.user_disconnected(session_id).await?,
            Message::UserTalking(audio_data) => self.user_talking(audio_data).await?,
        }

        Ok(())
    }

    async fn handle_audio_packet(&mut self, packet: AudioPacket) -> Result<(), Error> {
        match packet {
            AudioPacket::Ping(_) => {
                if !self.is_audio_tunneling && self.audio_channel_sender.is_some() {
                    self.audio_channel_sender
                        .as_mut()
                        .unwrap()
                        .send(packet)
                        .await?;
                } else {
                    self.control_channel_sender
                        .send(MumblePacket::UdpTunnel(packet))
                        .await?;
                }
            }
            AudioPacket::AudioData(mut audio_data) => {
                audio_data.session_id = Some(self.session_id);
                // It isn't critical to lose some audio packets
                self.response_sender
                    .try_send(ResponseMessage::Talking(audio_data));
            }
        }

        Ok(())
    }

    async fn new_user_connected(&mut self, session_id: u32) -> Result<(), Error> {
        if let Some(user) = self.db.get_user_by_session_id(session_id).await {
            self.control_channel_sender
                .send(MumblePacket::from(user))
                .await?;
        }
        Ok(())
    }

    async fn user_disconnected(&mut self, session_id: u32) -> Result<(), Error> {
        let mut user_remove = UserRemove::new();
        user_remove.set_session(session_id);
        Ok(self
            .control_channel_sender
            .send(MumblePacket::UserRemove(user_remove))
            .await?)
    }

    async fn self_disconnected(&mut self) {
        self.db.remove_connected_user(self.session_id).await;
        self.response_sender
            .send(ResponseMessage::Disconnected)
            .await;
    }

    async fn user_talking(&mut self, audio_data: AudioData) -> Result<(), Error> {
        let audio_packet = AudioPacket::AudioData(audio_data);

        if !self.is_audio_tunneling && self.audio_channel_sender.is_some() {
            self.audio_channel_sender
                .as_mut()
                .unwrap()
                .send(audio_packet)
                .await?;
        } else {
            self.control_channel_sender
                .send(MumblePacket::UdpTunnel(audio_packet))
                .await?;
        }

        Ok(())
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
