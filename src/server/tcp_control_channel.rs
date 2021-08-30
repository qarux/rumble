use crate::protocol::connection::{ControlChannel, ControlChannelStats, Error};
use crate::protocol::parser::{ControlMessage, Message, ParsingError};
use async_trait::async_trait;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;

const MAX_PROTOBUF_MESSAGE_SIZE: u32 = 8 * 1024 * 1024 - 1;

pub struct TcpControlChannel {
    received: AtomicU32,
    writer: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    reader: Mutex<ReadHalf<TlsStream<TcpStream>>>,
}

impl TcpControlChannel {
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);

        TcpControlChannel {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            received: AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl ControlChannel for TcpControlChannel {
    async fn send(&self, message: impl Message + 'async_trait) -> Result<(), Error> {
        let bytes = message.serialize();
        let mut writer = self.writer.lock().await;
        writer.write_all(&bytes).await?;
        Ok(())
    }

    async fn receive(&self) -> Result<ControlMessage, Error> {
        let mut packet_type = [0; 2];
        let mut length = [0; 4];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut packet_type).await?;
        reader.read_exact(&mut length).await?;
        let (packet_type, length) = ControlMessage::parse_prefix(packet_type, length);

        if length > MAX_PROTOBUF_MESSAGE_SIZE {
            return Err(Error::IO(std::io::Error::new(
                ErrorKind::Other,
                "too big message",
            )));
        }

        let mut payload = vec![0; length as usize];
        reader.read_exact(&mut payload).await?;
        let message = ControlMessage::parse_payload(packet_type, &payload)?;

        self.received.fetch_add(1, Ordering::Relaxed);
        Ok(message)
    }

    fn get_stats(&self) -> ControlChannelStats {
        ControlChannelStats {
            received: self.received.load(Ordering::Acquire),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<ParsingError> for Error {
    fn from(err: ParsingError) -> Self {
        Error::Parsing(err)
    }
}
