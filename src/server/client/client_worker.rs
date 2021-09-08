use crate::protocol::connection::{AudioChannel, ControlChannel};
use crate::protocol::parser::{AudioData, AudioPacket, TextMessage, UserState};
use crate::server::client::handler::{Config, ConnectionSetupError, Handler, HandlerError};
use crate::storage::Storage;
use log::error;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;

pub struct ClientWorker<C: ControlChannel, A: AudioChannel> {
    event_sender: Sender<ServerEvent>,
    audio_channel_sender: Sender<A>,
    task: JoinHandle<()>,
    control_channel_type: PhantomData<C>,
    audio_channel_type: PhantomData<A>,
}

pub enum ClientEvent {
    Talking(AudioData),
    StateChanged(UserState),
    TextMessage(TextMessage),
    Disconnected,
}

pub enum ServerEvent {
    Connected(u32),
    Talking(AudioData),
    StateChanged(UserState),
    TextMessage(TextMessage),
    Disconnected(u32),
}

impl<C: ControlChannel + 'static, A: AudioChannel + 'static> ClientWorker<C, A> {
    pub async fn setup_connection(
        session_id: u32,
        storage: Arc<Storage>,
        control_channel: C,
        config: Config,
    ) -> Result<(Self, Receiver<ClientEvent>), ConnectionSetupError> {
        let control_channel = Arc::new(control_channel);
        let (event_sender, event_receiver) = mpsc::channel(1);
        let (server_event_sender, server_event_receiver) = mpsc::channel(1);
        let (audio_sender, audio_receiver) = mpsc::channel(1);
        let handler: Handler<C, A> = Handler::new(
            storage,
            Arc::clone(&control_channel),
            event_sender,
            session_id,
            config,
        );
        handler.handle_new_connection().await?;
        let client = ClientWorker {
            event_sender: server_event_sender,
            audio_channel_sender: audio_sender,
            task: Self::run_handler_loop(
                handler,
                control_channel,
                server_event_receiver,
                audio_receiver,
            )
            .await,
            control_channel_type: Default::default(),
            audio_channel_type: Default::default(),
        };
        Ok((client, event_receiver))
    }

    pub async fn send_event(&self, event: ServerEvent) {
        if self.event_sender.send(event).await.is_err() {
            todo!()
        }
    }

    pub async fn set_audio_channel(&mut self, channel: A) {
        if self.audio_channel_sender.send(channel).await.is_err() {
            todo!()
        }
    }

    async fn run_handler_loop(
        handler: Handler<C, A>,
        control_channel: Arc<C>,
        event_receiver: Receiver<ServerEvent>,
        channel_receiver: Receiver<A>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            match Self::handler_loop(handler, control_channel, event_receiver, channel_receiver)
                .await
            {
                Err(HandlerError::PacketParsing(_) | HandlerError::IO(_)) => {
                    todo!()
                }
                Err(HandlerError::EventReceiverClosed) => {
                    error!("Server event receiver have been dropped");
                }
                Ok(_) => {}
            }
        })
    }

    // TODO cleaner solution
    async fn handler_loop(
        mut handler: Handler<C, A>,
        control_channel: Arc<C>,
        mut event_receiver: Receiver<ServerEvent>,
        mut channel_receiver: Receiver<A>,
    ) -> Result<(), HandlerError> {
        let mut audio_channel: Option<Arc<A>> = None;
        let msg_recv_fut = control_channel.receive();
        let audio_recv_fut = Self::recv(audio_channel.clone());
        tokio::pin!(msg_recv_fut, audio_recv_fut);

        loop {
            tokio::select! {
                result = &mut msg_recv_fut => {
                    match result {
                        Ok(msg) => {
                            msg_recv_fut.set(control_channel.receive());
                            handler.handle_message(msg).await?;
                        }
                        Err(crate::protocol::connection::Error::Parsing(_)) => {
                            // TODO
                            // Ignore for now
                            msg_recv_fut.set(control_channel.receive());
                        }
                        Err(_) => {
                            handler.self_disconnected().await?;
                            break;
                        }
                    }
                }
                Some(event) = event_receiver.recv() => {
                    handler.handle_server_event(event).await?;
                }
                Some(channel) = channel_receiver.recv() => {
                    let channel = Arc::new(channel);
                    handler.set_audio_channel(Arc::clone(&channel));
                    audio_channel = Some(channel);
                    audio_recv_fut.set(Self::recv(audio_channel.clone()));
                }
                Some(result) = &mut audio_recv_fut => {
                    match result {
                        Ok(packet) => {
                            audio_recv_fut.set(Self::recv(audio_channel.clone()));
                            handler.handle_audio_packet(packet).await?;
                        }
                        Err(_) => {
                            handler.self_disconnected().await?;
                            break;
                        }
                    }
                }
            };
        }

        Ok(())
    }

    async fn recv(
        audio_channel: Option<Arc<A>>,
    ) -> Option<Result<AudioPacket, crate::protocol::connection::Error>> {
        if let Some(channel) = audio_channel {
            Some(channel.receive().await)
        } else {
            std::future::pending().await
        }
    }
}

impl<C: ControlChannel, A: AudioChannel> Drop for ClientWorker<C, A> {
    fn drop(&mut self) {
        self.task.abort();
    }
}
