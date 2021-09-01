use crate::protocol::mumble;
use protobuf::{Message as ProtobufMessage, ProtobufError, SingularField};
use std::num::NonZeroU32;

pub const MUMBLE_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 3,
    patch: 4,
};

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

pub trait Message: Into<ControlMessage> + Send {
    fn serialize(self) -> Vec<u8>;
}

pub enum ControlMessage {
    Acl(),
    Authenticate(Authenticate),
    BanList(),
    ChannelRemove(),
    ChannelState(ChannelState),
    CodecVersion(CodecVersion),
    ContextAction(),
    ContextActionModify(),
    CryptSetup(CryptSetup),
    PermissionDenied(),
    PermissionQuery(),
    Ping(Ping),
    QueryUsers(),
    Reject(),
    RequestBlob(),
    ServerConfig(ServerConfig),
    ServerSync(ServerSync),
    SuggestConfig(),
    TextMessage(TextMessage),
    UserList(),
    UserRemove(UserRemove),
    UserState(UserState),
    UserStats(),
    UdpTunnel(UdpTunnel),
    Version(Version),
    VoiceTarget(),
}

pub enum AudioPacket {
    Ping(AudioPing),
    AudioData(AudioData),
}

#[derive(Clone)]
pub enum SessionId {
    // 0 is reserved for SuperUser
    SuperUser,
    User(NonZeroU32),
}

#[derive(Debug)]
pub enum ParsingError {
    MalformedInput,
}

#[derive(Clone)]
pub struct AudioData {
    pub session_id: Option<SessionId>,
    packet: Vec<u8>,
}

pub struct AudioPing {
    packet: Vec<u8>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u8,
    pub patch: u8,
}

#[derive(Default)]
pub struct Authenticate {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Default)]
pub struct ChannelState {
    pub id: Option<u32>,
    pub name: Option<String>,
}

pub struct CodecVersion {
    pub celt_alpha_version: i32,
    pub celt_beta_version: i32,
    pub prefer_alpha: bool,
    pub opus_support: bool,
}

#[derive(Default)]
pub struct CryptSetup {
    pub key: Option<Vec<u8>>,
    pub client_nonce: Option<Vec<u8>>,
    pub server_nonce: Option<Vec<u8>>,
}

#[derive(Default)]
pub struct Ping {
    pub timestamp: Option<u64>,
    pub good: Option<u32>,
    pub late: Option<u32>,
    pub lost: Option<u32>,
    pub resyncs: Option<u32>,
}

pub struct ServerConfig {
    pub max_users: u32,
    pub max_message_length: u32,
}

pub struct ServerSync {
    pub user_session_id: SessionId,
    pub max_bandwidth: u32,
    pub welcome_text: String,
}

#[derive(Clone)]
pub struct TextMessage {
    pub sender: Option<SessionId>,
    pub targets: Vec<u32>,
    pub message: String,
}

pub struct UserRemove {
    pub session_id: SessionId,
}

#[derive(Default, Clone)]
pub struct UserState {
    pub session_id: Option<SessionId>,
    pub name: Option<String>,
    pub channel_id: Option<u32>,
    pub muted_by_admin: Option<bool>,
    pub deafened_by_admin: Option<bool>,
    pub self_mute: Option<bool>,
    pub self_deaf: Option<bool>,
}

pub struct UdpTunnel {
    pub audio_packet: AudioPacket,
}

#[derive(Default)]
pub struct Version {
    pub version: Option<ProtocolVersion>,
}

impl ControlMessage {
    pub fn parse_prefix(packet_type: [u8; TYPE_SIZE], length: [u8; LENGTH_SIZE]) -> (u16, u32) {
        (u16::from_be_bytes(packet_type), u32::from_be_bytes(length))
    }

    pub fn parse_payload(packet_type: u16, payload: &[u8]) -> Result<Self, ParsingError> {
        Ok(match packet_type {
            AUTHENTICATE => {
                Authenticate::from(mumble::Authenticate::parse_from_bytes(payload)?).into()
            }
            CRYPT_SETUP => CryptSetup::from(mumble::CryptSetup::parse_from_bytes(payload)?).into(),
            PING => Ping::from(mumble::Ping::parse_from_bytes(payload)?).into(),
            TEXT_MESSAGE => {
                TextMessage::from(mumble::TextMessage::parse_from_bytes(payload)?).into()
            }
            USER_STATE => UserState::from(mumble::UserState::parse_from_bytes(payload)?).into(),
            UDP_TUNNEL => ControlMessage::UdpTunnel(UdpTunnel {
                audio_packet: AudioPacket::parse(payload.to_vec())?,
            }),
            VERSION => Version::from(mumble::Version::parse_from_bytes(payload)?).into(),
            // TODO
            _ => return Err(ParsingError::MalformedInput),
        })
    }
}

impl AudioPacket {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ParsingError> {
        let header = bytes.first().unwrap();
        let (packet_type, _) = decode_header(*header);
        if packet_type == 1 {
            return Ok(AudioPacket::Ping(AudioPing { packet: bytes }));
        }

        Ok(AudioPacket::AudioData(AudioData {
            session_id: None,
            packet: bytes,
        }))
    }

    pub fn serialize(self) -> Vec<u8> {
        match self {
            AudioPacket::Ping(ping) => ping.packet,
            AudioPacket::AudioData(audio_data) => {
                if let Some(session_id) = audio_data.session_id {
                    let mut bytes = audio_data.packet;
                    let varint = encode_varint(u32::from(session_id) as u64);
                    return std::iter::once(bytes.remove(0))
                        .chain(varint)
                        .chain(bytes)
                        .collect();
                }
                audio_data.packet
            }
        }
    }
}

fn serialize_protobuf_message<T>(message: T, packet_type: u16) -> Vec<u8>
where
    T: ProtobufMessage,
{
    let bytes = message.write_to_bytes().unwrap();
    return packet_type
        .to_be_bytes()
        .iter()
        .cloned()
        .chain((bytes.len() as u32).to_be_bytes().iter().cloned())
        .chain(bytes.into_iter())
        .collect();
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

impl Message for Authenticate {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::Authenticate {
            username: SingularField::from(self.username),
            password: SingularField::from(self.password),
            ..Default::default()
        };
        serialize_protobuf_message(proto, AUTHENTICATE)
    }
}

impl Message for ChannelState {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::ChannelState {
            channel_id: self.id,
            name: SingularField::from(self.name),
            ..Default::default()
        };
        serialize_protobuf_message(proto, CHANNEL_STATE)
    }
}

impl Message for CodecVersion {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::CodecVersion {
            alpha: Some(self.celt_alpha_version),
            beta: Some(self.celt_beta_version),
            prefer_alpha: Some(self.prefer_alpha),
            opus: Some(self.opus_support),
            ..Default::default()
        };

        serialize_protobuf_message(proto, CODEC_VERSION)
    }
}

impl Message for CryptSetup {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::CryptSetup {
            key: SingularField::from(self.key),
            client_nonce: SingularField::from(self.client_nonce),
            server_nonce: SingularField::from(self.server_nonce),
            ..Default::default()
        };
        serialize_protobuf_message(proto, CRYPT_SETUP)
    }
}

impl Message for Ping {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::Ping {
            timestamp: self.timestamp,
            good: self.good,
            late: self.late,
            lost: self.lost,
            resync: self.resyncs,
            ..Default::default()
        };
        serialize_protobuf_message(proto, PING)
    }
}

impl Message for ServerConfig {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::ServerConfig {
            max_users: Some(self.max_users),
            message_length: Some(self.max_message_length),
            ..Default::default()
        };
        serialize_protobuf_message(proto, SERVER_CONFIG)
    }
}

impl Message for ServerSync {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::ServerSync {
            session: Some(u32::from(self.user_session_id)),
            max_bandwidth: Some(self.max_bandwidth),
            welcome_text: SingularField::some(self.welcome_text),
            ..Default::default()
        };
        serialize_protobuf_message(proto, SERVER_SYNC)
    }
}

impl Message for TextMessage {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::TextMessage {
            actor: self.sender.map(u32::from),
            session: self.targets,
            message: SingularField::some(self.message),
            ..Default::default()
        };
        serialize_protobuf_message(proto, TEXT_MESSAGE)
    }
}

impl Message for UserRemove {
    fn serialize(self) -> Vec<u8> {
        let proto = mumble::UserRemove {
            session: Some(u32::from(self.session_id)),
            ..Default::default()
        };
        serialize_protobuf_message(proto, USER_REMOVE)
    }
}

impl Message for UserState {
    fn serialize(self) -> Vec<u8> {
        let mut proto = mumble::UserState {
            name: SingularField::from(self.name),
            channel_id: self.channel_id,
            mute: self.muted_by_admin,
            deaf: self.deafened_by_admin,
            self_mute: self.self_mute,
            self_deaf: self.self_deaf,
            ..Default::default()
        };
        if let Some(session) = self.session_id {
            proto.session = Some(u32::from(session));
        }

        serialize_protobuf_message(proto, USER_STATE)
    }
}

impl Message for UdpTunnel {
    fn serialize(self) -> Vec<u8> {
        let bytes = self.audio_packet.serialize();
        return UDP_TUNNEL
            .to_be_bytes()
            .iter()
            .cloned()
            .chain((bytes.len() as u32).to_be_bytes().iter().cloned())
            .chain(bytes)
            .collect();
    }
}

impl Message for Version {
    fn serialize(self) -> Vec<u8> {
        let mut proto = mumble::Version::new();
        if let Some(version) = self.version {
            proto.version = Some(u32::from(version))
        }

        serialize_protobuf_message(proto, VERSION)
    }
}

impl From<Authenticate> for ControlMessage {
    fn from(auth: Authenticate) -> Self {
        ControlMessage::Authenticate(auth)
    }
}

impl From<ChannelState> for ControlMessage {
    fn from(state: ChannelState) -> Self {
        ControlMessage::ChannelState(state)
    }
}

impl From<CodecVersion> for ControlMessage {
    fn from(codec_version: CodecVersion) -> Self {
        ControlMessage::CodecVersion(codec_version)
    }
}

impl From<CryptSetup> for ControlMessage {
    fn from(crypt: CryptSetup) -> Self {
        ControlMessage::CryptSetup(crypt)
    }
}

impl From<Ping> for ControlMessage {
    fn from(ping: Ping) -> Self {
        ControlMessage::Ping(ping)
    }
}

impl From<ServerConfig> for ControlMessage {
    fn from(config: ServerConfig) -> Self {
        ControlMessage::ServerConfig(config)
    }
}

impl From<ServerSync> for ControlMessage {
    fn from(sync: ServerSync) -> Self {
        ControlMessage::ServerSync(sync)
    }
}

impl From<TextMessage> for ControlMessage {
    fn from(message: TextMessage) -> Self {
        ControlMessage::TextMessage(message)
    }
}

impl From<UserRemove> for ControlMessage {
    fn from(remove: UserRemove) -> Self {
        ControlMessage::UserRemove(remove)
    }
}

impl From<UserState> for ControlMessage {
    fn from(state: UserState) -> Self {
        ControlMessage::UserState(state)
    }
}

impl From<UdpTunnel> for ControlMessage {
    fn from(tunnel: UdpTunnel) -> Self {
        ControlMessage::UdpTunnel(tunnel)
    }
}

impl From<Version> for ControlMessage {
    fn from(version: Version) -> Self {
        ControlMessage::Version(version)
    }
}

impl From<mumble::Authenticate> for Authenticate {
    fn from(auth: mumble::Authenticate) -> Self {
        Authenticate {
            username: auth.username.into_option(),
            password: auth.password.into_option(),
        }
    }
}

impl From<mumble::CryptSetup> for CryptSetup {
    fn from(crypt: mumble::CryptSetup) -> Self {
        CryptSetup {
            key: crypt.key.into_option(),
            client_nonce: crypt.client_nonce.into_option(),
            server_nonce: crypt.server_nonce.into_option(),
        }
    }
}

impl From<mumble::Ping> for Ping {
    fn from(ping: mumble::Ping) -> Self {
        Ping {
            timestamp: ping.timestamp,
            good: ping.good,
            late: ping.resync,
            lost: ping.lost,
            resyncs: ping.resync,
        }
    }
}

impl From<mumble::TextMessage> for TextMessage {
    fn from(message: mumble::TextMessage) -> Self {
        TextMessage {
            sender: message.actor.map(SessionId::from),
            targets: message.session,
            message: message.message.unwrap(),
        }
    }
}

impl From<mumble::UserState> for UserState {
    fn from(state: mumble::UserState) -> Self {
        UserState {
            session_id: state.session.map(SessionId::from),
            name: state.name.into_option(),
            channel_id: state.channel_id,
            muted_by_admin: state.mute,
            deafened_by_admin: state.deaf,
            self_mute: state.self_mute,
            self_deaf: state.self_deaf,
        }
    }
}

impl From<mumble::Version> for Version {
    fn from(version: mumble::Version) -> Self {
        Version {
            version: version.version.map(ProtocolVersion::from),
        }
    }
}

impl From<AudioPacket> for UdpTunnel {
    fn from(packet: AudioPacket) -> Self {
        UdpTunnel {
            audio_packet: packet,
        }
    }
}

impl From<ProtocolVersion> for u32 {
    fn from(version: ProtocolVersion) -> Self {
        ((version.major as u32) << 16) | ((version.minor as u32) << 8) | (version.patch as u32)
    }
}

impl From<u32> for ProtocolVersion {
    fn from(encoded: u32) -> Self {
        ProtocolVersion {
            major: ((encoded & 0xFFFF0000) >> 16) as u16,
            minor: ((encoded & 0xFF00) >> 8) as u8,
            patch: (encoded & 0xFF) as u8,
        }
    }
}

impl From<u32> for SessionId {
    fn from(session_id: u32) -> Self {
        if let Some(non_zero) = NonZeroU32::new(session_id) {
            SessionId::User(non_zero)
        } else {
            SessionId::SuperUser
        }
    }
}

impl From<SessionId> for u32 {
    fn from(session_id: SessionId) -> Self {
        match session_id {
            SessionId::SuperUser => 0,
            SessionId::User(id) => id.into(),
        }
    }
}

impl From<ProtobufError> for ParsingError {
    fn from(_: ProtobufError) -> Self {
        ParsingError::MalformedInput
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_conversion() {
        let encoded = 0x10302;
        let version = ProtocolVersion {
            major: 1,
            minor: 3,
            patch: 2,
        };
        assert_eq!(encoded, u32::from(version.clone()));
        assert_eq!(ProtocolVersion::from(encoded), version);
    }

    #[test]
    fn test_serialize_protobuf_message() {
        let version = mumble::Version {
            version: Some(12345),
            release: SingularField::some("release".to_owned()),
            os: SingularField::some("os".to_owned()),
            os_version: SingularField::some("os_version".to_owned()),
            ..Default::default()
        };
        let version_serialized = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x1c, 0x08, 0xb9, 0x60, 0x12, 0x07, 0x72, 0x65, 0x6c, 0x65,
            0x61, 0x73, 0x65, 0x1a, 0x02, 0x6f, 0x73, 0x22, 0x0a, 0x6f, 0x73, 0x5f, 0x76, 0x65,
            0x72, 0x73, 0x69, 0x6f, 0x6e,
        ];

        let user_state = mumble::UserState {
            session: Some(42),
            mute: Some(false),
            ..Default::default()
        };
        let user_state_serialized = vec![0x0, 0x9, 0x0, 0x0, 0x0, 0x4, 0x08, 0x2a, 0x30, 0x00];

        let ping = mumble::Ping {
            timestamp: Some(123456789),
            ..Default::default()
        };
        let ping_serialized = vec![0x0, 0x3, 0x0, 0x0, 0x0, 0x5, 0x8, 0x95, 0x9a, 0xef, 0x3a];

        assert_eq!(
            serialize_protobuf_message(version, VERSION),
            version_serialized
        );
        assert_eq!(
            serialize_protobuf_message(user_state, USER_STATE),
            user_state_serialized
        );
        assert_eq!(serialize_protobuf_message(ping, PING), ping_serialized);
    }

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
