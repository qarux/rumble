use crate::crypto;
use crate::crypto::Ocb2Aes128Crypto;
use crate::protocol::connection::{AudioChannel, AudioChannelStats, Error};
use crate::protocol::parser::AudioPacket;
use async_trait::async_trait;
use dashmap::DashMap;
use log::error;
use std::convert::TryInto;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

const MAX_AUDIO_PACKET_SIZE: usize = 1020;
const ENCRYPTION_OVERHEAD: usize = 4;
const MAX_DATAGRAM_SIZE: usize = MAX_AUDIO_PACKET_SIZE + ENCRYPTION_OVERHEAD;
const INFO_PING_SIZE: usize = 12;
const RESPONSE_SIZE: usize = 4 + 8 + 4 + 4 + 4;

type AudioChannelSenders = Arc<DashMap<SocketAddr, Sender<Vec<u8>>>>;
type AudioChannelQueue =
    Arc<DashMap<IpAddr, Vec<(Ocb2Aes128Crypto, oneshot::Sender<UdpAudioChannel>)>>>;

pub struct UdpWorker {
    queue: AudioChannelQueue,
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
    receiver: Mutex<Receiver<Vec<u8>>>,
    crypto: Mutex<Ocb2Aes128Crypto>,
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
    senders: AudioChannelSenders,
}

impl UdpWorker {
    pub async fn start(socket: UdpSocket, info: ServerInfo) -> Self {
        let socket = Arc::new(socket);
        let senders: AudioChannelSenders = Default::default();
        let queue: AudioChannelQueue = Default::default();
        let task = Self::run_task(socket, senders, Arc::clone(&queue), info).await;

        UdpWorker { queue, task }
    }

    // FIXME remove item from the queue on abort
    pub async fn new_audio_channel(&self, ip: IpAddr, crypto: Ocb2Aes128Crypto) -> UdpAudioChannel {
        let (sender, receiver) = oneshot::channel();
        let item = (crypto, sender);
        if let Some(list) = self.queue.get_mut(&ip).as_deref_mut() {
            list.push(item);
        } else {
            self.queue.insert(ip, vec![item]);
        }

        receiver.await.unwrap()
    }

    async fn run_task(
        socket: Arc<UdpSocket>,
        senders: AudioChannelSenders,
        queue: AudioChannelQueue,
        info: ServerInfo,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = [0; MAX_DATAGRAM_SIZE];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, address)) => {
                        if len <= ENCRYPTION_OVERHEAD || len > MAX_DATAGRAM_SIZE {
                            continue;
                        } else if len == INFO_PING_SIZE {
                            if let Err(err) = Self::response_to_ping(
                                &buf[..12].try_into().unwrap(),
                                &socket,
                                address,
                                &info,
                            )
                            .await
                            {
                                error!("UDP socket error: {}", err);
                                break;
                            };
                        } else if let Some(sender) = senders.get(&address).as_deref() {
                            sender.send(Vec::from(&buf[..len])).await.unwrap();
                        } else {
                            Self::check_queue(
                                &queue,
                                &buf[..len],
                                address,
                                Arc::clone(&socket),
                                Arc::clone(&senders),
                            );
                        }
                    }
                    Err(err) => {
                        error!("UDP socket error: {}", err);
                        break;
                    }
                }
            }
        })
    }

    fn check_queue(
        queue: &AudioChannelQueue,
        data: &[u8],
        address: SocketAddr,
        socket: Arc<UdpSocket>,
        senders: AudioChannelSenders,
    ) {
        let mut remove = false;
        if let Some(list) = queue.get_mut(&address.ip()).as_deref_mut() {
            let index = match list.iter_mut().position(|el| el.0.decrypt(data).is_ok()) {
                Some(index) => index,
                None => return,
            };
            let (crypto, channel_sender) = list.remove(index);
            let (sender, receiver) = mpsc::channel(1);
            senders.insert(address, sender);
            let channel = UdpAudioChannel {
                good: AtomicU32::new(crypto.good),
                late: AtomicU32::new(crypto.late),
                lost: AtomicU32::new(crypto.lost),
                received: AtomicU32::new(crypto.good + crypto.late),
                receiver: Mutex::new(receiver),
                crypto: Mutex::new(crypto),
                socket,
                destination: address,
                senders,
            };
            channel_sender.send(channel).ok();

            if list.is_empty() {
                remove = true;
            }
        }
        if remove {
            queue.remove(&address.ip());
        }
    }

    async fn response_to_ping(
        ping: &[u8; INFO_PING_SIZE],
        socket: &UdpSocket,
        origin: SocketAddr,
        info: &ServerInfo,
    ) -> std::io::Result<usize> {
        let bytes = Self::create_response(ping, info);
        socket.send_to(&bytes, origin).await
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
        let data = match receiver.recv().await {
            Some(data) => data,
            None => {
                return Err(Error::IO(IoError::new(
                    ErrorKind::BrokenPipe,
                    "receiver closed",
                )))
            }
        };
        drop(receiver);

        let mut crypto = self.crypto.lock().await;
        let decrypted = crypto.decrypt(&data)?;
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

impl Drop for UdpAudioChannel {
    fn drop(&mut self) {
        self.senders.remove(&self.destination);
    }
}

impl From<crypto::Error> for Error {
    fn from(_: crypto::Error) -> Self {
        Error::IO(IoError::new(ErrorKind::InvalidData, "crypto fail"))
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
