use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::connection::{Connection, ControlChannelWriter};
use crate::db::{Db, User};
use crate::proto::mumble::{Ping, UserRemove, UserState};
use crate::protocol::{AudioData, MumblePacket, VoicePacket};
use crate::client::Error::StreamError;

pub struct Client {
    pub session_id: u32,
    inner_sender: UnboundedSender<InnerMessage>,
    handler_task: JoinHandle<()>,
    packet_task: JoinHandle<()>,
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
    StreamError,
}

struct Handler {
    db: Arc<Db>,
    writer: ControlChannelWriter,
    session_id: u32,
    response_sender: UnboundedSender<ResponseMessage>,
}

enum InnerMessage {
    Message(Message),
    Packet(MumblePacket),
    Disconnected,
}

type ResponseReceiver = UnboundedReceiver<ResponseMessage>;

impl Client {
    pub async fn new(connection: Connection, db: Arc<Db>) -> (Client, ResponseReceiver) {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let (response_sender, response_receiver) = mpsc::unbounded_channel();

        let (mut reader, writer) = connection.control_channel.split();
        let session_id = connection.session_id;
        let handler_task = tokio::spawn(async move {
            let mut handler = Handler {
                db,
                writer,
                session_id,
                response_sender,
            };
            loop {
                let message = match receiver.recv().await {
                    Some(msg) => msg,
                    None => return,
                };

                match message {
                    InnerMessage::Message(msg) => {
                        let result = handler.handle_message(msg).await;
                        if result.is_err() {
                            return;
                        }
                    }
                    InnerMessage::Packet(packet) => {
                        let result = handler.handle_packet(packet).await;
                        if result.is_err() {
                            return;
                        }
                    }
                    InnerMessage::Disconnected => {
                        handler.self_disconnected().await;
                        return;
                    }
                }
            }
        });

        let inner_sender = sender.clone();
        let packet_task = tokio::spawn(async move {
            loop {
                match reader.read().await {
                    Ok(packet) => sender.send(InnerMessage::Packet(packet)),
                    Err(_) => {
                        sender.send(InnerMessage::Disconnected);
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
            },
            response_receiver,
        );
    }

    pub fn post_message(&self, message: Message) {
        self.inner_sender.send(InnerMessage::Message(message));
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.handler_task.abort();
        self.packet_task.abort();
    }
}

impl Handler {
    async fn handle_packet(&mut self, packet: MumblePacket) -> Result<(), Error> {
        match packet {
            MumblePacket::Ping(ping) => {
                if ping.has_timestamp() {
                    let mut ping = Ping::new();
                    ping.set_timestamp(ping.get_timestamp());
                    self.writer.write(MumblePacket::Ping(ping)).await?;
                }
            }
            MumblePacket::UdpTunnel(voice) => match voice {
                VoicePacket::Ping(_) => {
                    self.writer.write(MumblePacket::UdpTunnel(voice)).await;
                }
                VoicePacket::AudioData(mut audio_data) => {
                    audio_data.session_id = Some(self.session_id);
                    self.response_sender
                        .send(ResponseMessage::Talking(audio_data));
                }
            },
            _ => println!("unimplemented!"),
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

    async fn new_user_connected(&mut self, session_id: u32) -> Result<(), Error> {
        if let Some(user) = self.db.get_user_by_session_id(session_id).await {
            self.writer.write(MumblePacket::from(user)).await?;
        }
        Ok(())
    }

    async fn user_disconnected(&mut self, session_id: u32) -> Result<(), Error> {
        let mut user_remove = UserRemove::new();
        user_remove.set_session(session_id);
        Ok(self
            .writer
            .write(MumblePacket::UserRemove(user_remove))
            .await?)
    }

    async fn self_disconnected(&mut self) {
        self.db.remove_connected_user(self.session_id).await;
        self.response_sender.send(ResponseMessage::Disconnected);
    }

    async fn user_talking(&mut self, audio_data: AudioData) -> Result<(), Error> {
        Ok(self
            .writer
            .write(MumblePacket::UdpTunnel(VoicePacket::AudioData(audio_data)))
            .await?)
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
