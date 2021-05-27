use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::db::Db;
use crate::proto::mumble::{
    ChannelState, CodecVersion, PermissionQuery, ServerConfig, ServerSync, UserState, Version,
};
use crate::protocol::{
    MumblePacket, MumblePacketReader, MumblePacketWriter, MUMBLE_PROTOCOL_VERSION,
};

pub struct Connection<S> {
    pub reader: MumblePacketReader<ReadHalf<S>>,
    pub writer: MumblePacketWriter<WriteHalf<S>>,
    pub session_id: u32,
}

pub struct ConnectionConfig {
    pub max_bandwidth: u32,
    pub welcome_text: String,
}

pub enum Error {
    ConnectionSetupError,
    AuthenticationError,
    StreamError(crate::protocol::Error),
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub async fn setup_connection(
        db: Arc<Db>,
        stream: S,
        config: ConnectionConfig,
    ) -> Result<Connection<S>, Error> {
        let (mut reader, mut writer) = crate::protocol::new(stream);

        //Version exchange
        let _ = match reader.read().await? {
            MumblePacket::Version(version) => version,
            _ => return Err(Error::ConnectionSetupError),
        };
        let mut version = Version::new();
        version.set_version(MUMBLE_PROTOCOL_VERSION);
        writer.write(MumblePacket::Version(version)).await?;

        //Authentication
        let mut auth = match reader.read().await? {
            MumblePacket::Authenticate(auth) => auth,
            _ => return Err(Error::ConnectionSetupError),
        };
        if !auth.has_username() {
            return Err(Error::AuthenticationError);
        }
        let session_id = db.add_new_user(auth.take_username()).await;

        //Crypt setup TODO

        //CodecVersion
        let mut codec_version = CodecVersion::new();
        codec_version.set_alpha(-2147483632);
        codec_version.set_beta(0);
        codec_version.set_prefer_alpha(true);
        codec_version.set_opus(true);
        writer
            .write(MumblePacket::CodecVersion(codec_version))
            .await?;

        //Channel state
        let channels = db.get_channels().await;
        for channel in channels {
            let mut channel_state = ChannelState::new();
            channel_state.set_channel_id(channel.id);
            channel_state.set_name(channel.name);
            writer
                .write(MumblePacket::ChannelState(channel_state))
                .await?;
        }

        //PermissionQuery
        let mut permission_query = PermissionQuery::new();
        permission_query.set_permissions(134743822);
        permission_query.set_channel_id(0);
        writer
            .write(MumblePacket::PermissionQuery(permission_query))
            .await?;

        //User states
        let connected_users = db.get_connected_users().await;
        for user in connected_users {
            let mut user_state = UserState::new();
            user_state.set_name(user.username);
            user_state.set_session(user.session_id);
            user_state.set_channel_id(user.channel_id);
            writer.write(MumblePacket::UserState(user_state)).await?;
        }

        //Server sync
        let mut server_sync = ServerSync::new();
        server_sync.set_session(session_id);
        server_sync.set_welcome_text(config.welcome_text);
        server_sync.set_max_bandwidth(config.max_bandwidth);
        server_sync.set_permissions(134743822);
        writer.write(MumblePacket::ServerSync(server_sync)).await?;

        //ServerConfig
        let mut server_config = ServerConfig::new();
        server_config.set_max_users(10);
        server_config.set_allow_html(true);
        server_config.set_message_length(5000);
        server_config.set_image_message_length(131072);
        writer
            .write(MumblePacket::ServerConfig(server_config))
            .await?;

        Ok(Connection {
            reader,
            writer,
            session_id,
        })
    }
}

impl From<crate::protocol::Error> for Error {
    fn from(err: crate::protocol::Error) -> Self {
        Error::StreamError(err)
    }
}
