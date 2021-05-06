use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncRead};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::connection::Connection;
use crate::db::{Db, User};
use crate::protocol::{MumblePacket, VoicePacket, MumblePacketWriter};
use crate::proto::mumble::{UserState, Ping};
use tokio::task::JoinHandle;

pub enum Message {
    NewUser(u32)
}

pub struct Client {
    inner_sender: UnboundedSender<InnerMessage>,
    handler_task: JoinHandle<()>,
    packet_task: JoinHandle<()>,
}

pub enum Error {
    UserNotFound,
    StreamError(crate::protocol::Error),
}

struct Handler<W> {
    db: Arc<Db>,
    writer: MumblePacketWriter<W>,
    response_sender: UnboundedSender<Message>,
}

enum InnerMessage {
    Message(Message),
    Packet(MumblePacket),
}

type ResponseReceiver = UnboundedReceiver<Message>;

impl Client {
    pub async fn new<S>(connection: Connection<S>, db: Arc<Db>) -> (Client, ResponseReceiver)
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let (response_sender, response_receiver) = mpsc::unbounded_channel();

        let writer = connection.writer;
        let handler_task = tokio::spawn(async move {
            let mut handler = Handler {
                db,
                writer,
                response_sender,
            };
            loop {
                let message = match receiver.recv().await {
                    None => return,
                    Some(msg) => msg,
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
                }
            }
        });

        let inner_sender = sender.clone();
        let mut reader = connection.reader;
        let packet_task = tokio::spawn(async move {
            loop {
                let packet = match reader.read().await{
                    Ok(packet) => packet,
                    Err(_) => return, //TODO
                };

                sender.send(InnerMessage::Packet(packet));
            }
        });

        return (Client {
            inner_sender,
            handler_task,
            packet_task,
        }, response_receiver);
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

impl<W> Handler<W>
    where
        W: AsyncWrite + Unpin + Send,
{
    async fn handle_packet(&mut self, packet: MumblePacket) -> Result<(), Error> {
        match packet {
            MumblePacket::Ping(ping) => {
                if ping.has_timestamp() {
                    let mut ping = Ping::new();
                    ping.set_timestamp(ping.get_timestamp());
                    self.writer.write(MumblePacket::Ping(ping)).await?;
                }
            }
            MumblePacket::UdpTunnel(voice) => {
                match voice {
                    VoicePacket::Ping(_) => {
                        self.writer.write(MumblePacket::UdpTunnel(voice));
                        println!("VoicePing");
                    }
                    VoicePacket::AudioData(_) => { println!("AudioData"); }
                }
            }
            _ => println!("unimplemented!")
        }
        Ok(())
    }

    async fn handle_message(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::NewUser(session_id) => self.new_user_connected(session_id).await?,
        }

        Ok(())
    }

    async fn new_user_connected(&mut self, session_id: u32) -> Result<(), Error> {
        if let Some(user) = self.db.get_user_by_session_id(session_id).await {
            self.writer.write(MumblePacket::from(user)).await?;
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
    fn from(err: crate::protocol::Error) -> Self {
        Error::StreamError(err)
    }
}

