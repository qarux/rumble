use protobuf::{Message, ProtobufError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::mumble::{ACL as Acl, Authenticate, BanList, ChannelRemove, ChannelState,
                           CodecVersion, ContextAction, ContextActionModify, CryptSetup, PermissionDenied,
                           PermissionQuery, Ping, QueryUsers, Reject, RequestBlob,
                           ServerConfig, ServerSync, SuggestConfig, TextMessage, UserList,
                           UserRemove, UserState, UserStats, Version, VoiceTarget};

pub const MUMBLE_PROTOCOL_VERSION: u32 = 0b0000_0001_0011_0100;

const VERSION: u16 = 0;
const UDP_TUNNEL: u16 = 1;
const AUTHENTICATE: u16 = 2;
const PING: u16 = 3;
const REJECT: u16 = 4;
const SERVER_SYNC: u16 = 5;
const CHANNEL_REMOVE: u16 = 6;
const CHANNEL_STATE: u16 = 7;
const USER_REMOVE: u16 = 8;
const USER_STATE: u16 = 9;
const BAN_LIST: u16 = 10;
const TEXT_MESSAGE: u16 = 11;
const PERMISSION_DENIED: u16 = 12;
const ACL: u16 = 13;
const QUERY_USERS: u16 = 14;
const CRYPT_SETUP: u16 = 15;
const CONTEXT_ACTION_MODIFY: u16 = 16;
const CONTEXT_ACTION: u16 = 17;
const USER_LIST: u16 = 18;
const VOICE_TARGET: u16 = 19;
const PERMISSION_QUERY: u16 = 20;
const CODEC_VERSION: u16 = 21;
const USER_STATS: u16 = 22;
const REQUEST_BLOB: u16 = 23;
const SERVER_CONFIG: u16 = 24;
const SUGGEST_CONFIG: u16 = 25;
const MAX_AUDIO_PACKET_SIZE: usize = 1020;

pub enum MumblePacket {
    Version(Version),
    UdpTunnel(VoicePacket),
    Authenticate(Authenticate),
    Ping(Ping),
    Reject(Reject),
    ServerSync(ServerSync),
    ChannelRemove(ChannelRemove),
    ChannelState(ChannelState),
    UserRemove(UserRemove),
    UserState(UserState),
    BanList(BanList),
    TextMessage(TextMessage),
    PermissionDenied(PermissionDenied),
    Acl(Acl),
    QueryUsers(QueryUsers),
    CryptSetup(CryptSetup),
    ContextActionModify(ContextActionModify),
    ContextAction(ContextAction),
    UserList(UserList),
    VoiceTarget(VoiceTarget),
    PermissionQuery(PermissionQuery),
    CodecVersion(CodecVersion),
    UserStats(UserStats),
    RequestBlob(RequestBlob),
    ServerConfig(ServerConfig),
    SuggestConfig(SuggestConfig),
}

pub enum VoicePacket {
    Ping(VoicePing),
    AudioData(AudioData),
}

pub enum Error {
    UnknownPacketType,
    ConnectionError,
    ParsingError,
}

pub struct MumblePacketReader<R> {
    reader: R,
}

pub struct MumblePacketWriter<W> {
    writer: W,
}

pub struct VoicePing {
    timestamp: u64,
}

pub struct AudioData {
    codec: Codecs,
    target: u8,
    session_id: Option<u64>,
    sequence_number: u64,
    audio_payload: Vec<u8>,
    positional_info: Option<[f32; 3]>,
}

enum Codecs {
    CeltAlpha,
    Speex,
    CeltBeta,
    Opus,
}

pub fn new<S, R, W>(stream: S) -> (MumblePacketReader<R>, MumblePacketWriter<W>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
{
    let (reader, writer) = tokio::io::split(stream);
    (MumblePacketReader { reader }, MumblePacketWriter { writer })
}

impl<R> MumblePacketReader<R>
    where
        R: AsyncRead + Unpin + Send,
{
    pub async fn read(&mut self) -> Result<MumblePacket, Error> {
        let packet_type = self.reader.read_u16().await?;
        let payload_length = self.reader.read_u32().await?;

        if packet_type == UDP_TUNNEL {
            return Ok(MumblePacket::UdpTunnel(self.read_voice_packet().await?));
        }

        let payload = self.read_payload(payload_length).await?;

        match packet_type {
            VERSION => Ok(MumblePacket::Version(Version::parse_from_bytes(&payload)?)),
            AUTHENTICATE => Ok(MumblePacket::Authenticate(Authenticate::parse_from_bytes(&payload)?)),
            PING => Ok(MumblePacket::Ping(Ping::parse_from_bytes(&payload)?)),
            REJECT => Ok(MumblePacket::Reject(Reject::parse_from_bytes(&payload)?)),
            SERVER_SYNC => Ok(MumblePacket::ServerSync(ServerSync::parse_from_bytes(&payload)?)),
            CHANNEL_REMOVE => Ok(MumblePacket::ChannelRemove(ChannelRemove::parse_from_bytes(&payload)?)),
            CHANNEL_STATE => Ok(MumblePacket::ChannelState(ChannelState::parse_from_bytes(&payload)?)),
            USER_REMOVE => Ok(MumblePacket::UserRemove(UserRemove::parse_from_bytes(&payload)?)),
            USER_STATE => Ok(MumblePacket::UserState(UserState::parse_from_bytes(&payload)?)),
            BAN_LIST => Ok(MumblePacket::BanList(BanList::parse_from_bytes(&payload)?)),
            TEXT_MESSAGE => Ok(MumblePacket::TextMessage(TextMessage::parse_from_bytes(&payload)?)),
            PERMISSION_DENIED => Ok(MumblePacket::PermissionDenied(PermissionDenied::parse_from_bytes(&payload)?)),
            ACL => Ok(MumblePacket::Acl(Acl::parse_from_bytes(&payload)?)),
            QUERY_USERS => Ok(MumblePacket::QueryUsers(QueryUsers::parse_from_bytes(&payload)?)),
            CRYPT_SETUP => Ok(MumblePacket::CryptSetup(CryptSetup::parse_from_bytes(&payload)?)),
            CONTEXT_ACTION_MODIFY => Ok(MumblePacket::ContextActionModify(ContextActionModify::parse_from_bytes(&payload)?)),
            CONTEXT_ACTION => Ok(MumblePacket::ContextAction(ContextAction::parse_from_bytes(&payload)?)),
            USER_LIST => Ok(MumblePacket::UserList(UserList::parse_from_bytes(&payload)?)),
            VOICE_TARGET => Ok(MumblePacket::VoiceTarget(VoiceTarget::parse_from_bytes(&payload)?)),
            PERMISSION_QUERY => Ok(MumblePacket::PermissionQuery(PermissionQuery::parse_from_bytes(&payload)?)),
            CODEC_VERSION => Ok(MumblePacket::CodecVersion(CodecVersion::parse_from_bytes(&payload)?)),
            USER_STATS => Ok(MumblePacket::UserStats(UserStats::parse_from_bytes(&payload)?)),
            REQUEST_BLOB => Ok(MumblePacket::RequestBlob(RequestBlob::parse_from_bytes(&payload)?)),
            SERVER_CONFIG => Ok(MumblePacket::ServerConfig(ServerConfig::parse_from_bytes(&payload)?)),
            SUGGEST_CONFIG => Ok(MumblePacket::SuggestConfig(SuggestConfig::parse_from_bytes(&payload)?)),
            _ => Err(Error::UnknownPacketType)
        }
    }

    async fn read_voice_packet(&mut self) -> Result<VoicePacket, Error> {
        let header = self.reader.read_u8().await?;
        let (audio_packet_type, target) = decode_header(header);

        if audio_packet_type == 1 {
            let timestamp = self.read_varint().await?;
            return Ok(VoicePacket::Ping(VoicePing {
                timestamp
            }));
        }

        let codec = match audio_packet_type {
            0 => Codecs::CeltAlpha,
            2 => Codecs::Speex,
            3 => Codecs::CeltBeta,
            4 => Codecs::Opus,
            _ => return Err(Error::ParsingError)
        };
        let sequence_number = self.read_varint().await?;
        let audio_payload = self.read_audio_payload(&codec).await?;
        Ok(VoicePacket::AudioData(AudioData {
            codec,
            target,
            session_id: None,
            sequence_number,
            audio_payload,
            positional_info: None, //TODO
        }))
    }

    async fn read_varint(&mut self) -> Result<u64, Error> { //TODO negative number decode
        let header = self.reader.read_u8().await?;

        //7-bit number
        if (header & 0b1000_0000) == 0b0000_0000 {
            return Ok(header as u64);
        }
        //14-bit number
        if (header & 0b1100_0000) == 0b1000_0000 {
            let first_number_byte = header ^ 0b1000_0000;
            return Ok(
                ((first_number_byte as u64) << 8) |
                    (self.reader.read_u8().await? as u64)
            );
        }
        //21-bit number
        if (header & 0b1110_0000) == 0b1100_0000 {
            let first_number_byte = header ^ 0b1100_0000;
            return Ok(
                ((first_number_byte as u64) << 16) |
                    ((self.reader.read_u8().await? as u64) << 8) |
                    (self.reader.read_u8().await? as u64)
            );
        }
        //28-bit number
        if (header & 0b1111_0000) == 0b1110_0000 {
            let first_number_byte = header ^ 0b1110_0000;
            return Ok(
                ((first_number_byte as u64) << 24) |
                    ((self.reader.read_u8().await? as u64) << 16) |
                    ((self.reader.read_u8().await? as u64) << 8) |
                    (self.reader.read_u8().await? as u64)
            );
        }
        //32-bit number
        if (header & 0b1111_1100) == 0b1111_0000 {
            return Ok(self.reader.read_u32().await? as u64);
        }
        //64-bit number
        if (header & 0b1111_1100) == 0b1111_0100 {
            return Ok(self.reader.read_u64().await?);
        }

        Err(Error::ParsingError)
    }

    async fn read_audio_payload(&mut self, codec_type: &Codecs) -> Result<Vec<u8>, Error> {
        match codec_type {
            Codecs::CeltAlpha | Codecs::Speex | Codecs::CeltBeta => {
                let mut payload = vec![];
                loop {
                    let header = self.reader.read_u8().await?;
                    let continuation_bit = header & 0b1000_0000;
                    let length = header & 0b0111_1111;
                    payload.push(header);
                    if length == 0 {
                        payload.push(0);
                        break;
                    }
                    for _ in 0..length {
                        payload.push(self.reader.read_u8().await?)
                    }

                    if continuation_bit == 0 {
                        break;
                    }
                    if payload.len() > MAX_AUDIO_PACKET_SIZE {
                        return Err(Error::ParsingError);
                    }
                }
                Ok(payload)
            }
            Codecs::Opus => {
                let mut payload = vec![];
                let header = self.read_varint().await?;
                let length = header & 0x1fff;
                payload.append(&mut encode_varint(header));

                for _ in 0..length {
                    payload.push(self.reader.read_u8().await?)
                }
                Ok(payload)
            }
        }
    }

    async fn read_payload(&mut self, payload_length: u32) -> tokio::io::Result<Vec<u8>> {
        let mut payload = vec![0; payload_length as usize];
        self.reader.read_exact(&mut payload).await?;
        Ok(payload)
    }
}

impl<W> MumblePacketWriter<W>
    where
        W: AsyncWrite + Unpin + Send,
{
    pub async fn write(&mut self, packet: MumblePacket) -> Result<(), Error> {
        match packet {
            MumblePacket::UdpTunnel(value) => {
                let bytes = serialize_voice_packet(value);
                self.writer.write_u16(UDP_TUNNEL).await?;
                self.writer.write_u32(bytes.len() as u32).await?;
                self.writer.write_all(&bytes).await?;
            }
            MumblePacket::Version(value) => self.write_protobuf_packet(value, VERSION).await?,
            MumblePacket::Authenticate(value) => self.write_protobuf_packet(value, AUTHENTICATE).await?,
            MumblePacket::Ping(value) => self.write_protobuf_packet(value, PING).await?,
            MumblePacket::Reject(value) => self.write_protobuf_packet(value, REJECT).await?,
            MumblePacket::ServerSync(value) => self.write_protobuf_packet(value, SERVER_SYNC).await?,
            MumblePacket::ChannelRemove(value) => self.write_protobuf_packet(value, CHANNEL_REMOVE).await?,
            MumblePacket::ChannelState(value) => self.write_protobuf_packet(value, CHANNEL_STATE).await?,
            MumblePacket::UserRemove(value) => self.write_protobuf_packet(value, USER_REMOVE).await?,
            MumblePacket::UserState(value) => self.write_protobuf_packet(value, USER_STATE).await?,
            MumblePacket::BanList(value) => self.write_protobuf_packet(value, BAN_LIST).await?,
            MumblePacket::TextMessage(value) => self.write_protobuf_packet(value, TEXT_MESSAGE).await?,
            MumblePacket::PermissionDenied(value) => self.write_protobuf_packet(value, PERMISSION_DENIED).await?,
            MumblePacket::Acl(value) => self.write_protobuf_packet(value, ACL).await?,
            MumblePacket::QueryUsers(value) => self.write_protobuf_packet(value, QUERY_USERS).await?,
            MumblePacket::CryptSetup(value) => self.write_protobuf_packet(value, CRYPT_SETUP).await?,
            MumblePacket::ContextActionModify(value) => self.write_protobuf_packet(value, CONTEXT_ACTION_MODIFY).await?,
            MumblePacket::ContextAction(value) => self.write_protobuf_packet(value, CONTEXT_ACTION).await?,
            MumblePacket::UserList(value) => self.write_protobuf_packet(value, USER_LIST).await?,
            MumblePacket::VoiceTarget(value) => self.write_protobuf_packet(value, VOICE_TARGET).await?,
            MumblePacket::PermissionQuery(value) => self.write_protobuf_packet(value, PERMISSION_QUERY).await?,
            MumblePacket::CodecVersion(value) => self.write_protobuf_packet(value, CODEC_VERSION).await?,
            MumblePacket::UserStats(value) => self.write_protobuf_packet(value, USER_STATS).await?,
            MumblePacket::RequestBlob(value) => self.write_protobuf_packet(value, REQUEST_BLOB).await?,
            MumblePacket::ServerConfig(value) => self.write_protobuf_packet(value, SERVER_CONFIG).await?,
            MumblePacket::SuggestConfig(value) => self.write_protobuf_packet(value, SUGGEST_CONFIG).await?,
        }

        self.writer.flush().await?;
        Ok(())
    }

    async fn write_protobuf_packet<T>(&mut self, packet: T, packet_type: u16) -> Result<(), Error>
        where T: Message
    {
        let bytes = packet.write_to_bytes()?;
        self.writer.write_u16(packet_type).await?;
        self.writer.write_u32(bytes.len() as u32).await?;
        self.writer.write_all(&bytes).await?;

        Ok(())
    }
}

fn decode_header(header: u8) -> (u8, u8) {
    let packet_type = header >> 5;
    let target = header & 0b0001_1111;
    (packet_type, target)
}

fn encode_header(packet_type: u8, target: u8) -> u8 {
    (packet_type << 5) | target
}

fn encode_varint(number: u64) -> Vec<u8> { //TODO negative number encode
    let mut result = vec![];

    if number < 0x80 {
        //7-bit number
        result.push(number as u8);
    } else if number < 0x4000 {
        //14-bit number
        result.push(((number >> 8) | 0x80) as u8);
        result.push((number & 0xFF) as u8);
    } else if number < 0x200000 {
        //21-bit number
        result.push(((number >> 16) | 0xC0) as u8);
        result.push(((number >> 8) & 0xFF) as u8);
        result.push((number & 0xFF) as u8);
    } else if number < 0x10000000 {
        //28-bit number
        result.push(((number >> 24) | 0xE0) as u8);
        result.push(((number >> 16) & 0xFF) as u8);
        result.push(((number >> 8) & 0xFF) as u8);
        result.push((number & 0xFF) as u8);
    } else if number < 0x100000000 {
        //32-bit number
        result.push(0xF0);
        result.push(((number >> 24) & 0xFF) as u8);
        result.push(((number >> 16) & 0xFF) as u8);
        result.push(((number >> 8) & 0xFF) as u8);
        result.push((number & 0xFF) as u8);
    } else {
        //64-bit number
        result.push(0xF4);
        result.push(((number >> 56) & 0xFF) as u8);
        result.push(((number >> 48) & 0xFF) as u8);
        result.push(((number >> 40) & 0xFF) as u8);
        result.push(((number >> 32) & 0xFF) as u8);
        result.push(((number >> 24) & 0xFF) as u8);
        result.push(((number >> 16) & 0xFF) as u8);
        result.push(((number >> 8) & 0xFF) as u8);
        result.push((number & 0xFF) as u8);
    }

    result
}

fn serialize_voice_packet(packet: VoicePacket) -> Vec<u8> {
    let mut result = vec![];

    match packet {
        VoicePacket::Ping(value) => {
            result.push(0b0010_0000);
            let mut varint = encode_varint(value.timestamp);
            result.append(&mut varint);
        }
        VoicePacket::AudioData(mut value) => {
            let packet_type = match value.codec {
                Codecs::CeltAlpha => 0b0000_0000,
                Codecs::Speex => 0b0100_0000,
                Codecs::CeltBeta => 0b0110_0000,
                Codecs::Opus => 0b1000_0000,
            };
            let header = encode_header(packet_type, value.target);
            result.push(header);

            if let Some(session_id) = value.session_id {
                let mut session_id = encode_varint(session_id);
                result.append(&mut session_id);
            }

            let mut sequence_number = encode_varint(value.sequence_number);
            result.append(&mut sequence_number);

            result.append(&mut value.audio_payload);

            if let Some(position_info) = value.positional_info {
                result.extend_from_slice(&position_info[0].to_be_bytes());
                result.extend_from_slice(&position_info[1].to_be_bytes());
                result.extend_from_slice(&position_info[2].to_be_bytes());
            }
        }
    }

    result
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::ConnectionError
    }
}

impl From<ProtobufError> for Error {
    fn from(error: ProtobufError) -> Self {
        match error {
            ProtobufError::IoError(_) | ProtobufError::WireError(_) => Error::ConnectionError,
            ProtobufError::Utf8(_) | ProtobufError::MessageNotInitialized { .. } => Error::ParsingError
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn test_decode_header() {
        assert_eq!(decode_header(0b0100_1000), (2, 8));
        assert_eq!(decode_header(0b0111_1111), (3, 31));
        assert_eq!(decode_header(0b1000_0000), (4, 0));
    }

    #[test]
    fn test_encode_header() {
        assert_eq!(encode_header(2, 8), 0b0100_1000);
        assert_eq!(encode_header(3, 31), 0b0111_1111);
        assert_eq!(encode_header(4, 0), 0b1000_0000);
    }

    #[test]
    fn test_encode_varint() {
        let varint_7bit_positive = vec![0b0000_1000];
        let varint_14bit_positive = vec![0b1010_0010, 0b0000_0011];
        let varint_21bit_positive = vec![0b1101_0100, 0b0000_0000, 0b0000_0000];
        let varint_28bit_positive =
            vec![0b1110_1100, 0b0100_0000, 0b0010_0000, 0b0000_0001];
        let varint_32bit_positive =
            vec![0b1111_0000, 0b1100_0000, 0b0000_0000, 0b0000_0000, 0b0000_0001];
        let varint_64bit_positive =
            vec![0b1111_0100, 0b1100_0000, 0b0000_0000, 0b0000_0000, 0b0000_0001,
                 0b0000_0000, 0b0000_0000, 0b0000_0000, 0b0001_0000];

        assert_eq!(encode_varint(0x8), varint_7bit_positive);
        assert_eq!(encode_varint(0x2203), varint_14bit_positive);
        assert_eq!(encode_varint(0x140000), varint_21bit_positive);
        assert_eq!(encode_varint(0xc402001), varint_28bit_positive);
        assert_eq!(encode_varint(0xc0000001), varint_32bit_positive);
        assert_eq!(encode_varint(0xc000000100000010), varint_64bit_positive);
    }
}

