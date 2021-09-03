use crate::crypto;
use crate::crypto::Ocb2Aes128Crypto;
use crate::protocol::connection::{AudioChannel, AudioChannelStats, Error};
use crate::protocol::parser::AudioPacket;
use async_trait::async_trait;
use std::convert::TryInto;
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
const INFO_PING_SIZE: usize = 12;
const RESPONSE_SIZE: usize = 4 + 8 + 4 + 4 + 4;

type Data = Arc<(Vec<u8>, SocketAddr)>;

pub struct UdpWorker {
    sender: Sender<Data>,
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
}

pub struct ServerInfo {
    pub version: u32,
    pub connected_users: Arc<AtomicU32>,
    pub max_users: u32,
    pub max_bandwidth: u32,
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
    pub async fn start(socket: UdpSocket, info: ServerInfo) -> Self {
        let (sender, _) = broadcast::channel(8);
        let socket = Arc::new(socket);
        let udp_socket = Arc::clone(&socket);
        let broadcast_sender = sender.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; MAX_DATAGRAM_SIZE];
            loop {
                if let Ok((len, address)) = udp_socket.recv_from(&mut buf).await {
                    if len == INFO_PING_SIZE {
                        Self::response_to_ping(
                            &buf[..12].try_into().unwrap(),
                            &udp_socket,
                            address,
                            &info,
                        )
                        .await;
                    } else {
                        broadcast_sender.send(Arc::new((Vec::from(&buf[..len]), address)));
                    }
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

    async fn response_to_ping(
        ping: &[u8; INFO_PING_SIZE],
        socket: &UdpSocket,
        origin: SocketAddr,
        info: &ServerInfo,
    ) {
        let bytes = Self::create_response(ping, info);
        socket.send_to(&bytes, origin).await;
    }

    fn create_response(ping: &[u8; INFO_PING_SIZE], info: &ServerInfo) -> [u8; RESPONSE_SIZE] {
        let mut response = [0u8; RESPONSE_SIZE];
        response[..4].copy_from_slice(&info.version.to_be_bytes());
        response[4..12].copy_from_slice(&ping[4..]);
        response[12..16]
            .copy_from_slice(&info.connected_users.load(Ordering::Acquire).to_be_bytes());
        response[16..20].copy_from_slice(&info.max_users.to_be_bytes());
        response[20..24].copy_from_slice(&info.max_bandwidth.to_be_bytes());
        response
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_response() {
        let ping = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 0];
        let info = ServerInfo {
            version: 0x0123,
            connected_users: Arc::new(AtomicU32::from(42)),
            max_users: 100,
            max_bandwidth: 100000,
        };

        let expected: [u8; RESPONSE_SIZE] = [
            0, 0, 1, 35, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 42, 0, 0, 0, 100, 0, 1, 134, 160,
        ];
        let response = UdpWorker::create_response(&ping, &info);
        assert_eq!(response, expected);
    }
}
