use protobuf::{Message, ProtobufError};

use crate::proto::mumble::{
    Authenticate, BanList, ChannelRemove, ChannelState, CodecVersion, ContextAction,
    ContextActionModify, CryptSetup, PermissionDenied, PermissionQuery, Ping, QueryUsers, Reject,
    RequestBlob, ServerConfig, ServerSync, SuggestConfig, TextMessage, UserList, UserRemove,
    UserState, UserStats, Version, VoiceTarget, ACL as Acl,
};

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

const TYPE_SIZE: usize = 2;
const LENGTH_SIZE: usize = 4;

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
    ParsingError,
}

pub struct VoicePing {
    bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct AudioData {
    pub session_id: Option<u32>,
    bytes: Vec<u8>,
}

impl MumblePacket {
    pub fn parse_prefix(packet_type: [u8; TYPE_SIZE], length: [u8; LENGTH_SIZE]) -> (u16, u32) {
        (u16::from_be_bytes(packet_type), u32::from_be_bytes(length))
    }

    pub fn parse_payload(packet_type: u16, payload: &[u8]) -> Result<Self, Error> {
        match packet_type {
            VERSION => Ok(MumblePacket::Version(Version::parse_from_bytes(payload)?)),
            UDP_TUNNEL => Ok(MumblePacket::UdpTunnel(VoicePacket::parse(
                payload.to_vec(),
            )?)),
            AUTHENTICATE => Ok(MumblePacket::Authenticate(Authenticate::parse_from_bytes(
                payload,
            )?)),
            PING => Ok(MumblePacket::Ping(Ping::parse_from_bytes(payload)?)),
            REJECT => Ok(MumblePacket::Reject(Reject::parse_from_bytes(payload)?)),
            SERVER_SYNC => Ok(MumblePacket::ServerSync(ServerSync::parse_from_bytes(
                payload,
            )?)),
            CHANNEL_REMOVE => Ok(MumblePacket::ChannelRemove(
                ChannelRemove::parse_from_bytes(payload)?,
            )),
            CHANNEL_STATE => Ok(MumblePacket::ChannelState(ChannelState::parse_from_bytes(
                payload,
            )?)),
            USER_REMOVE => Ok(MumblePacket::UserRemove(UserRemove::parse_from_bytes(
                payload,
            )?)),
            USER_STATE => Ok(MumblePacket::UserState(UserState::parse_from_bytes(
                payload,
            )?)),
            BAN_LIST => Ok(MumblePacket::BanList(BanList::parse_from_bytes(payload)?)),
            TEXT_MESSAGE => Ok(MumblePacket::TextMessage(TextMessage::parse_from_bytes(
                payload,
            )?)),
            PERMISSION_DENIED => Ok(MumblePacket::PermissionDenied(
                PermissionDenied::parse_from_bytes(payload)?,
            )),
            ACL => Ok(MumblePacket::Acl(Acl::parse_from_bytes(payload)?)),
            QUERY_USERS => Ok(MumblePacket::QueryUsers(QueryUsers::parse_from_bytes(
                payload,
            )?)),
            CRYPT_SETUP => Ok(MumblePacket::CryptSetup(CryptSetup::parse_from_bytes(
                payload,
            )?)),
            CONTEXT_ACTION_MODIFY => Ok(MumblePacket::ContextActionModify(
                ContextActionModify::parse_from_bytes(payload)?,
            )),
            CONTEXT_ACTION => Ok(MumblePacket::ContextAction(
                ContextAction::parse_from_bytes(payload)?,
            )),
            USER_LIST => Ok(MumblePacket::UserList(UserList::parse_from_bytes(payload)?)),
            VOICE_TARGET => Ok(MumblePacket::VoiceTarget(VoiceTarget::parse_from_bytes(
                payload,
            )?)),
            PERMISSION_QUERY => Ok(MumblePacket::PermissionQuery(
                PermissionQuery::parse_from_bytes(payload)?,
            )),
            CODEC_VERSION => Ok(MumblePacket::CodecVersion(CodecVersion::parse_from_bytes(
                payload,
            )?)),
            USER_STATS => Ok(MumblePacket::UserStats(UserStats::parse_from_bytes(
                payload,
            )?)),
            REQUEST_BLOB => Ok(MumblePacket::RequestBlob(RequestBlob::parse_from_bytes(
                payload,
            )?)),
            SERVER_CONFIG => Ok(MumblePacket::ServerConfig(ServerConfig::parse_from_bytes(
                payload,
            )?)),
            SUGGEST_CONFIG => Ok(MumblePacket::SuggestConfig(
                SuggestConfig::parse_from_bytes(&payload)?,
            )),
            _ => Err(Error::UnknownPacketType),
        }
    }

    pub fn serialize(self) -> Vec<u8> {
        match self {
            MumblePacket::UdpTunnel(voice_packet) => {
                let bytes = voice_packet.serialize();
                return UDP_TUNNEL
                    .to_be_bytes()
                    .iter()
                    .cloned()
                    .chain((bytes.len() as u32).to_be_bytes().iter().cloned())
                    .chain(bytes)
                    .collect();
            }
            MumblePacket::Version(value) => Self::serialize_protobuf_packet(&value, VERSION),
            MumblePacket::Authenticate(value) => {
                Self::serialize_protobuf_packet(&value, AUTHENTICATE)
            }
            MumblePacket::Ping(value) => Self::serialize_protobuf_packet(&value, PING),
            MumblePacket::Reject(value) => Self::serialize_protobuf_packet(&value, REJECT),
            MumblePacket::ServerSync(value) => Self::serialize_protobuf_packet(&value, SERVER_SYNC),
            MumblePacket::ChannelRemove(value) => {
                Self::serialize_protobuf_packet(&value, CHANNEL_REMOVE)
            }
            MumblePacket::ChannelState(value) => {
                Self::serialize_protobuf_packet(&value, CHANNEL_STATE)
            }
            MumblePacket::UserRemove(value) => Self::serialize_protobuf_packet(&value, USER_REMOVE),
            MumblePacket::UserState(value) => Self::serialize_protobuf_packet(&value, USER_STATE),
            MumblePacket::BanList(value) => Self::serialize_protobuf_packet(&value, BAN_LIST),
            MumblePacket::TextMessage(value) => {
                Self::serialize_protobuf_packet(&value, TEXT_MESSAGE)
            }
            MumblePacket::PermissionDenied(value) => {
                Self::serialize_protobuf_packet(&value, PERMISSION_DENIED)
            }
            MumblePacket::Acl(value) => Self::serialize_protobuf_packet(&value, ACL),
            MumblePacket::QueryUsers(value) => Self::serialize_protobuf_packet(&value, QUERY_USERS),
            MumblePacket::CryptSetup(value) => Self::serialize_protobuf_packet(&value, CRYPT_SETUP),
            MumblePacket::ContextActionModify(value) => {
                Self::serialize_protobuf_packet(&value, CONTEXT_ACTION_MODIFY)
            }
            MumblePacket::ContextAction(value) => {
                Self::serialize_protobuf_packet(&value, CONTEXT_ACTION)
            }
            MumblePacket::UserList(value) => Self::serialize_protobuf_packet(&value, USER_LIST),
            MumblePacket::VoiceTarget(value) => {
                Self::serialize_protobuf_packet(&value, VOICE_TARGET)
            }
            MumblePacket::PermissionQuery(value) => {
                Self::serialize_protobuf_packet(&value, PERMISSION_QUERY)
            }
            MumblePacket::CodecVersion(value) => {
                Self::serialize_protobuf_packet(&value, CODEC_VERSION)
            }
            MumblePacket::UserStats(value) => Self::serialize_protobuf_packet(&value, USER_STATS),
            MumblePacket::RequestBlob(value) => {
                Self::serialize_protobuf_packet(&value, REQUEST_BLOB)
            }
            MumblePacket::ServerConfig(value) => {
                Self::serialize_protobuf_packet(&value, SERVER_CONFIG)
            }
            MumblePacket::SuggestConfig(value) => {
                Self::serialize_protobuf_packet(&value, SUGGEST_CONFIG)
            }
        }
    }

    fn serialize_protobuf_packet<T>(packet: &T, packet_type: u16) -> Vec<u8>
    where
        T: Message,
    {
        let bytes = packet.write_to_bytes().unwrap();
        return packet_type
            .to_be_bytes()
            .iter()
            .cloned()
            .chain((bytes.len() as u32).to_be_bytes().iter().cloned())
            .chain(bytes)
            .collect();
    }
}

impl VoicePacket {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::ParsingError);
        }

        let header = bytes.first().unwrap();
        let (packet_type, _) = decode_header(*header);
        if packet_type == 1 {
            return Ok(VoicePacket::Ping(VoicePing { bytes }));
        }

        Ok(VoicePacket::AudioData(AudioData {
            session_id: None,
            bytes,
        }))
    }

    pub fn serialize(self) -> Vec<u8> {
        match self {
            VoicePacket::Ping(ping) => ping.bytes,
            VoicePacket::AudioData(audio_data) => {
                if let Some(session_id) = audio_data.session_id {
                    let mut bytes = audio_data.bytes;
                    let varint = encode_varint(session_id as u64);
                    return std::iter::once(bytes.remove(0))
                        .chain(varint)
                        .chain(bytes)
                        .collect();
                }
                audio_data.bytes
            }
        }
    }
}

fn decode_header(header: u8) -> (u8, u8) {
    let packet_type = header >> 5;
    let target = header & 0b0001_1111;
    (packet_type, target)
}

fn encode_varint(number: u64) -> Vec<u8> {
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

impl From<ProtobufError> for Error {
    fn from(_: ProtobufError) -> Self {
        Error::ParsingError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_header() {
        assert_eq!(decode_header(0b0100_1000), (2, 8));
        assert_eq!(decode_header(0b0111_1111), (3, 31));
        assert_eq!(decode_header(0b1000_0000), (4, 0));
    }

    #[test]
    fn test_encode_varint() {
        let varint_7bit_positive = vec![0b0000_1000];
        let varint_14bit_positive = vec![0b1010_0010, 0b0000_0011];
        let varint_21bit_positive = vec![0b1101_0100, 0b0000_0000, 0b0000_0000];
        let varint_28bit_positive = vec![0b1110_1100, 0b0100_0000, 0b0010_0000, 0b0000_0001];
        let varint_32bit_positive = vec![
            0b1111_0000,
            0b1100_0000,
            0b0000_0000,
            0b0000_0000,
            0b0000_0001,
        ];
        let varint_64bit_positive = vec![
            0b1111_0100,
            0b1100_0000,
            0b0000_0000,
            0b0000_0000,
            0b0000_0001,
            0b0000_0000,
            0b0000_0000,
            0b0000_0000,
            0b0001_0000,
        ];

        assert_eq!(encode_varint(0x8), varint_7bit_positive);
        assert_eq!(encode_varint(0x2203), varint_14bit_positive);
        assert_eq!(encode_varint(0x140000), varint_21bit_positive);
        assert_eq!(encode_varint(0xc402001), varint_28bit_positive);
        assert_eq!(encode_varint(0xc0000001), varint_32bit_positive);
        assert_eq!(encode_varint(0xc000000100000010), varint_64bit_positive);
    }
}
