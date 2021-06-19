use std::sync::Arc;

use crate::protocol::{AudioPacket, MumblePacket};

use crate::crypto::Ocb2Aes128Crypto;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use tokio::sync::mpsc::Receiver;
use tokio_rustls::TlsStream;

pub struct ControlChannel {
    receiver: ControlChannelReceiver,
    sender: ControlChannelSender,
}

pub struct AudioChannel {
    receiver: AudioChannelReceiver,
    sender: AudioChannelSender,
}

pub struct ControlChannelReceiver {
    reader: ReadHalf<TlsStream<TcpStream>>,
}

pub struct ControlChannelSender {
    writer: WriteHalf<TlsStream<TcpStream>>,
}

pub struct AudioChannelReceiver {
    raw_bytes_receiver: Receiver<Vec<u8>>,
    crypto: Arc<Mutex<Ocb2Aes128Crypto>>,
}

pub struct AudioChannelSender {
    socket: Arc<UdpSocket>,
    crypto: Arc<Mutex<Ocb2Aes128Crypto>>,
    destination: SocketAddr,
}

pub enum Error {
    IOError(std::io::Error),
    ParsingError(crate::protocol::Error),
    CryptError(crate::crypto::Error),
}

impl ControlChannel {
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let receiver = ControlChannelReceiver { reader };
        let sender = ControlChannelSender { writer };

        ControlChannel { receiver, sender }
    }

    pub async fn receive(&mut self) -> Result<MumblePacket, Error> {
        self.receiver.receive().await
    }

    pub async fn send(&mut self, packet: MumblePacket) -> Result<(), Error> {
        self.sender.send(packet).await
    }

    pub fn split(self) -> (ControlChannelReceiver, ControlChannelSender) {
        (self.receiver, self.sender)
    }
}

impl AudioChannel {
    pub fn new(
        incoming_bytes_receiver: Receiver<Vec<u8>>,
        socket: Arc<UdpSocket>,
        crypto: Ocb2Aes128Crypto,
        destination: SocketAddr,
    ) -> Self {
        let crypto = Arc::new(Mutex::new(crypto));
        let receiver = AudioChannelReceiver {
            raw_bytes_receiver: incoming_bytes_receiver,
            crypto: Arc::clone(&crypto),
        };
        let sender = AudioChannelSender {
            socket,
            crypto: Arc::clone(&crypto),
            destination,
        };

        AudioChannel { receiver, sender }
    }

    pub fn split(self) -> (AudioChannelReceiver, AudioChannelSender) {
        (self.receiver, self.sender)
    }
}

impl ControlChannelReceiver {
    pub async fn receive(&mut self) -> Result<MumblePacket, Error> {
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

impl ControlChannelSender {
    pub async fn send(&mut self, packet: MumblePacket) -> Result<(), Error> {
        let bytes = packet.serialize();
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

impl AudioChannelSender {
    pub async fn send(&mut self, packet: AudioPacket) -> Result<(), Error> {
        let bytes = packet.serialize();
        let encrypted = {
            let mut crypto = self.crypto.lock().await;
            crypto.encrypt(&bytes)?
        };
        self.socket.send_to(&encrypted, self.destination).await?;
        Ok(())
    }
}

impl AudioChannelReceiver {
    pub async fn receive(&mut self) -> Result<AudioPacket, Error> {
        match self.raw_bytes_receiver.recv().await {
            Some(bytes) => {
                let decrypted = {
                    let mut crypto = self.crypto.lock().await;
                    crypto.decrypt(&bytes)?
                };
                Ok(AudioPacket::parse(decrypted)?)
            }
            None => unimplemented!(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IOError(error)
    }
}

impl From<crate::protocol::Error> for Error {
    fn from(error: crate::protocol::Error) -> Self {
        Error::ParsingError(error)
    }
}

impl From<crate::crypto::Error> for Error {
    fn from(error: crate::crypto::Error) -> Self {
        Error::CryptError(error)
    }
}
