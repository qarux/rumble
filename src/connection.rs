use std::sync::Arc;

use crate::protocol::{AudioPacket, MumblePacket};

use crate::crypto::Ocb2Aes128Crypto;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::mpsc::Receiver;
use tokio_rustls::TlsStream;

pub struct ControlChannel {
    pub packets_received: AtomicU32,
    writer: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    reader: Mutex<ReadHalf<TlsStream<TcpStream>>>,
}

pub struct AudioChannel {
    pub good: AtomicU32,
    pub late: AtomicU32,
    pub lost: AtomicU32,
    pub packets_received: AtomicU32,
    raw_bytes_receiver: Mutex<Receiver<Vec<u8>>>,
    crypto: Mutex<Ocb2Aes128Crypto>,
    socket: Arc<UdpSocket>,
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

        ControlChannel {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            packets_received: AtomicU32::new(0),
        }
    }

    pub async fn receive(&self) -> Result<MumblePacket, Error> {
        let mut packet_type = [0; 2];
        let mut length = [0; 4];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut packet_type).await?;
        reader.read_exact(&mut length).await?;
        let (packet_type, length) = MumblePacket::parse_prefix(packet_type, length);

        let mut payload = vec![0; length as usize];
        reader.read_exact(&mut payload).await?;
        let packet = MumblePacket::parse_payload(packet_type, &payload)?;

        self.packets_received.fetch_add(1, Ordering::Relaxed);
        Ok(packet)
    }

    pub async fn send(&self, packet: MumblePacket) -> Result<(), Error> {
        let bytes = packet.serialize();
        let mut writer = self.writer.lock().await;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn send_multiple(&self, packets: Vec<MumblePacket>) -> Result<(), Error> {
        for packet in packets {
            self.send(packet).await?;
        }

        Ok(())
    }
}

impl AudioChannel {
    pub fn new(
        raw_bytes_receiver: Receiver<Vec<u8>>,
        socket: Arc<UdpSocket>,
        crypto: Ocb2Aes128Crypto,
        destination: SocketAddr,
    ) -> Self {
        let crypto = Mutex::new(crypto);

        AudioChannel {
            raw_bytes_receiver: Mutex::new(raw_bytes_receiver),
            crypto,
            socket,
            destination,
            good: AtomicU32::new(0),
            late: AtomicU32::new(0),
            lost: AtomicU32::new(0),
            packets_received: AtomicU32::new(0),
        }
    }

    pub async fn receive(&self) -> Result<AudioPacket, Error> {
        let mut receiver = self.raw_bytes_receiver.lock().await;
        let bytes = match receiver.recv().await {
            Some(bytes) => bytes,
            None => unimplemented!(),
        };
        let mut crypto = self.crypto.lock().await;
        let decrypted = crypto.decrypt(&bytes)?;
        self.good.swap(crypto.good, Ordering::Release);
        self.late.swap(crypto.late, Ordering::Release);
        self.lost.swap(crypto.lost, Ordering::Release);
        drop(crypto);

        let packet = AudioPacket::parse(decrypted)?;
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        Ok(packet)
    }

    pub async fn send(&self, packet: AudioPacket) -> Result<(), Error> {
        let bytes = packet.serialize();
        let encrypted = {
            let mut crypto = self.crypto.lock().await;
            crypto.encrypt(&bytes)?
        };
        self.socket.send_to(&encrypted, self.destination).await?;
        Ok(())
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
