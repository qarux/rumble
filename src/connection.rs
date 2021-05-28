use std::sync::Arc;

use crate::db::Db;
use crate::proto::mumble::{
    ChannelState, CodecVersion, CryptSetup, PermissionQuery, ServerConfig, ServerSync, UserState,
    Version,
};
use crate::protocol::{MumblePacket, MUMBLE_PROTOCOL_VERSION};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;

pub struct Connection {
    pub control_channel: ControlChannel,
    pub session_id: u32,
}

pub struct ControlChannel {
    reader: ControlChannelReader,
    writer: ControlChannelWriter,
}

pub struct ControlChannelReader {
    reader: ReadHalf<TlsStream<TcpStream>>,
}

pub struct ControlChannelWriter {
    writer: WriteHalf<TlsStream<TcpStream>>,
}

pub struct ConnectionConfig {
    pub max_bandwidth: u32,
    pub welcome_text: String,
}

pub enum Error {
    ConnectionSetupError,
    AuthenticationError,
    StreamError,
}

impl Connection {
    pub async fn setup_connection(
        db: Arc<Db>,
        stream: TlsStream<TcpStream>,
        config: ConnectionConfig,
    ) -> Result<Connection, Error> {
        let mut control_channel = ControlChannel::new(stream);

        //Version exchange
        let _ = match control_channel.read().await? {
            MumblePacket::Version(version) => version,
            _ => return Err(Error::ConnectionSetupError),
        };
        let mut version = Version::new();
        version.set_version(MUMBLE_PROTOCOL_VERSION);
        control_channel
            .write(MumblePacket::Version(version))
            .await?;

        //Authentication
        let mut auth = match control_channel.read().await? {
            MumblePacket::Authenticate(auth) => auth,
            _ => return Err(Error::ConnectionSetupError),
        };
        if !auth.has_username() {
            return Err(Error::AuthenticationError);
        }
        let session_id = db.add_new_user(auth.take_username()).await;

        //Crypt setup

        //CodecVersion
        let mut codec_version = CodecVersion::new();
        codec_version.set_alpha(-2147483632);
        codec_version.set_beta(0);
        codec_version.set_prefer_alpha(true);
        codec_version.set_opus(true);
        control_channel
            .write(MumblePacket::CodecVersion(codec_version))
            .await?;

        //Channel state
        let channels = db.get_channels().await;
        for channel in channels {
            let mut channel_state = ChannelState::new();
            channel_state.set_channel_id(channel.id);
            channel_state.set_name(channel.name);
            control_channel
                .write(MumblePacket::ChannelState(channel_state))
                .await?;
        }

        //PermissionQuery
        let mut permission_query = PermissionQuery::new();
        permission_query.set_permissions(134743822);
        permission_query.set_channel_id(0);
        control_channel
            .write(MumblePacket::PermissionQuery(permission_query))
            .await?;

        //User states
        let connected_users = db.get_connected_users().await;
        for user in connected_users {
            let mut user_state = UserState::new();
            user_state.set_name(user.username);
            user_state.set_session(user.session_id);
            user_state.set_channel_id(user.channel_id);
            control_channel
                .write(MumblePacket::UserState(user_state))
                .await?;
        }

        //Server sync
        let mut server_sync = ServerSync::new();
        server_sync.set_session(session_id);
        server_sync.set_welcome_text(config.welcome_text);
        server_sync.set_max_bandwidth(config.max_bandwidth);
        server_sync.set_permissions(134743822);
        control_channel
            .write(MumblePacket::ServerSync(server_sync))
            .await?;

        //ServerConfig
        let mut server_config = ServerConfig::new();
        server_config.set_max_users(10);
        server_config.set_allow_html(true);
        server_config.set_message_length(5000);
        server_config.set_image_message_length(131072);
        control_channel
            .write(MumblePacket::ServerConfig(server_config))
            .await?;

        Ok(Connection {
            control_channel,
            session_id,
        })
    }
}

impl ControlChannel {
    pub async fn read(&mut self) -> Result<MumblePacket, Error> {
        self.reader.read().await
    }

    pub async fn write(&mut self, packet: MumblePacket) -> Result<(), Error> {
        self.writer.write(packet).await
    }

    pub fn split(self) -> (ControlChannelReader, ControlChannelWriter) {
        (self.reader, self.writer)
    }

    fn new(stream: TlsStream<TcpStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        ControlChannel {
            reader: ControlChannelReader { reader },
            writer: ControlChannelWriter { writer },
        }
    }
}

impl ControlChannelReader {
    pub async fn read(&mut self) -> Result<MumblePacket, Error> {
        let mut packet_type = [0; 2];
        let mut length = [0; 4];
        self.reader.read_exact(&mut packet_type).await?;
        self.reader.read_exact(&mut length).await?;
        let (packet_type, length) = MumblePacket::parse_prefix(packet_type, length);

        let mut payload = vec![0; length as usize];
        self.reader.read_exact(&mut payload).await?;
        Ok(MumblePacket::parse_payload(packet_type, &payload)?)
    }
}

impl ControlChannelWriter {
    pub async fn write(&mut self, packet: MumblePacket) -> Result<(), Error> {
        let bytes = packet.serialize();
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

impl From<crate::protocol::Error> for Error {
    fn from(_: crate::protocol::Error) -> Self {
        Error::StreamError
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::StreamError
    }
}
