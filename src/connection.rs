use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::db::{Db, User};
use crate::proto::mumble::{ChannelState, Ping, UserState, Version};
use crate::protocol::{MUMBLE_PROTOCOL_VERSION, MumblePacket, MumblePacketStream};

pub struct Connection<S> {
    db: Arc<Db>,
    stream: MumblePacketStream<S>,
}

pub enum Error {
    ConnectionSetupError,
    AuthenticationError,
}

impl<S> Connection<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub async fn setup_connection(db: Arc<Db>, mut stream: MumblePacketStream<S>) -> Result<Connection<S>, Error> {
        let _ = match stream.read().await? {
            MumblePacket::Version(version) => version,
            _ => return Err(Error::ConnectionSetupError)
        };
        let mut version = Version::new();
        version.set_version(MUMBLE_PROTOCOL_VERSION);
        stream.write(MumblePacket::Version(version)).await?;

        let auth = match stream.read().await? {
            MumblePacket::Authenticate(auth) => auth,
            _ => return Err(Error::ConnectionSetupError)
        };
        if !auth.has_username() {
            return Err(Error::AuthenticationError);
        }
        db.add_new_user(User {
            username: auth.get_username().to_string(),
            channel_id: 0,
            is_connected: true,
        }).await;

        //TODO UDP crypt setup

        let channels = db.get_channels();
        for channel in channels {
            let mut channel_state = ChannelState::new();
            channel_state.set_name(channel.name);
            channel_state.set_channel_id(channel.id);
            stream.write(MumblePacket::ChannelState(channel_state)).await?;
        }

        let connected_users = db.get_connected_users();
        for user in connected_users {
            let mut user_state = UserState::new();
            user_state.set_name(user.username);
            user_state.set_channel_id(user.channel_id);
            stream.write(MumblePacket::UserState(user_state)).await?;
        }

        Ok(Connection {
            db,
            stream,
        })
    }

    pub async fn read_packet(&mut self) -> Result<MumblePacket, Error> {
        Ok(self.stream.read().await?)
    }

    pub async fn handle_packet(&mut self, packet: MumblePacket) -> Result<(), Error> {
        match packet {
            MumblePacket::Ping(ping) => {
                if ping.has_timestamp() {
                    let mut ping = Ping::new();
                    ping.set_timestamp(ping.get_timestamp());
                    self.stream.write(MumblePacket::Ping(ping)).await?;
                }
            }
            _ => println!("unimplemented!")
        }
        Ok(())
    }
}

impl From<crate::protocol::Error> for Error {
    fn from(_: crate::protocol::Error) -> Self {
        Error::ConnectionSetupError
    }
}

