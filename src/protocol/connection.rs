use crate::protocol::parser::{AudioPacket, ControlMessage, Message};
use async_trait::async_trait;

#[async_trait]
pub trait ControlChannel: Send + Sync {
    async fn send(&self, message: impl Message + 'async_trait) -> Result<(), Error>;

    async fn receive(&self) -> Result<ControlMessage, Error>;

    fn get_stats(&self) -> ControlChannelStats;
}

#[async_trait]
pub trait AudioChannel: Send + Sync {
    async fn send(&self, packet: AudioPacket) -> Result<(), Error>;

    async fn receive(&self) -> Result<AudioPacket, Error>;

    fn get_stats(&self) -> AudioChannelStats;
}

pub struct ControlChannelStats {
    pub received: u32,
}

pub struct AudioChannelStats {
    pub good: u32,
    pub late: u32,
    pub lost: u32,
    pub received: u32,
}

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Parsing(crate::protocol::parser::ParsingError),
}
