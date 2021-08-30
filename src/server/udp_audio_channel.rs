use crate::crypto;
use crate::crypto::Ocb2Aes128Crypto;
use crate::protocol::connection::{AudioChannel, AudioChannelStats, Error};
use crate::protocol::parser::AudioPacket;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;

const MAX_AUDIO_PACKET_SIZE: usize = 1020;
const ENCRYPTION_OVERHEAD: usize = 4;
const MAX_DATAGRAM_SIZE: usize = MAX_AUDIO_PACKET_SIZE + ENCRYPTION_OVERHEAD;

type Data = Arc<(Vec<u8>, SocketAddr)>;

pub struct UdpWorker {
    sender: Sender<Data>,
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
}

pub struct UdpAudioChannel {
    good: AtomicU32,
    late: AtomicU32,
    lost: AtomicU32,
    received: AtomicU32,
    receiver: Mutex<Receiver<Data>>,
    crypto: Mutex<Ocb2Aes128Crypto>,
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
}

impl UdpWorker {
    pub async fn start(socket: UdpSocket) -> Self {
        let (sender, _) = broadcast::channel(8);
        let socket = Arc::new(socket);
        let udp_socket = Arc::clone(&socket);
        let broadcast_sender = sender.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; MAX_DATAGRAM_SIZE];
            loop {
                if let Ok((len, socket_address)) = udp_socket.recv_from(&mut buf).await {
                    broadcast_sender.send(Arc::new((Vec::from(&buf[..len]), socket_address)));
                }
            }
        });
        UdpWorker {
            sender,
            socket,
            task,
        }
    }

    pub async fn new_audio_channel(
        &self,
        ip: IpAddr,
        mut crypto: Ocb2Aes128Crypto,
    ) -> UdpAudioChannel {
        loop {
            let mut receiver = self.sender.subscribe();
            let data = match receiver.recv().await {
                Ok(data) => data,
                Err(RecvError::Lagged(_)) => receiver.recv().await.unwrap(),
                Err(_) => panic!(),
            };
            let (bytes, address) = data.as_ref();

            if address.ip() == ip && crypto.decrypt(bytes).is_ok() {
                return UdpAudioChannel {
                    good: AtomicU32::new(1),
                    late: AtomicU32::new(0),
                    lost: AtomicU32::new(0),
                    received: AtomicU32::new(1),
                    receiver: Mutex::new(receiver),
                    crypto: Mutex::new(crypto),
                    socket: Arc::clone(&self.socket),
                    destination: address.clone(),
                };
            }
        }
    }
}

#[async_trait]
impl AudioChannel for UdpAudioChannel {
    async fn send(&self, packet: AudioPacket) -> Result<(), Error> {
        let bytes = packet.serialize();
        let encrypted = {
            let mut crypto = self.crypto.lock().await;
            crypto.encrypt(&bytes)?
        };
        self.socket.send_to(&encrypted, self.destination).await?;
        Ok(())
    }

    async fn receive(&self) -> Result<AudioPacket, Error> {
        let mut receiver = self.receiver.lock().await;
        let data = loop {
            let data = match receiver.recv().await {
                Ok(data) => data,
                Err(RecvError::Lagged(_)) => receiver.recv().await.unwrap(),
                Err(_) => panic!(),
            };

            if data.1 == self.destination {
                break data;
            }
        };
        drop(receiver);

        let mut crypto = self.crypto.lock().await;
        let decrypted = crypto.decrypt(&data.0)?;
        self.good.swap(crypto.good, Ordering::Release);
        self.late.swap(crypto.late, Ordering::Release);
        self.lost.swap(crypto.lost, Ordering::Release);
        drop(crypto);

        let packet = AudioPacket::parse(decrypted)?;
        self.received.fetch_add(1, Ordering::Relaxed);
        Ok(packet)
    }

    fn get_stats(&self) -> AudioChannelStats {
        AudioChannelStats {
            good: self.good.load(Ordering::Acquire),
            late: self.late.load(Ordering::Acquire),
            lost: self.lost.load(Ordering::Acquire),
            received: self.received.load(Ordering::Acquire),
        }
    }
}

impl Drop for UdpWorker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl From<crypto::Error> for Error {
    fn from(_: crypto::Error) -> Self {
        Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "crypto fail",
        ))
    }
}
