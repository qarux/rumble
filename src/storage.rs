use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

const ROOT_CHANNEL_ID: u32 = 0;
const USER_TREE_NAME: &[u8] = b"users";
const CHANNEL_TREE_NAME: &[u8] = b"channels";

type Sha1Hash = [u8; 20];
type SessionId = u32;
type UserId = u32;
type ChannelId = u32;
type Username = String;

pub struct Storage {
    users: sled::Tree,
    channels: sled::Tree,
    session_data: DashMap<SessionId, SessionData>,
    guests: DashMap<SessionId, Guest>,
    connected_users: DashMap<SessionId, (UserId, Username)>,
    connected: Arc<AtomicU32>,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: Username,
    pub channel_id: ChannelId,
    pub comment: Option<String>,
    pub texture: Option<Vec<u8>>,
    pub certificate_hash: Option<Sha1Hash>,
    pub comment_hash: Option<Sha1Hash>,
    pub texture_hash: Option<Sha1Hash>,
    pub password_hash: Option<Vec<u8>>,
    pub password_salt: Option<Vec<u8>>,
    pub pbkdf2_iterations: Option<NonZeroU32>,
}

#[derive(Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub parent_id: Option<u32>,
    pub linked_channels: Vec<u32>,
    pub description: Option<String>,
    pub description_hash: Option<Sha1Hash>,
    pub max_users: Option<u32>,
    pub temporary: bool,
    pub position: Option<u32>,
}

#[derive(Clone)]
pub struct Guest {
    pub session_id: SessionId,
    pub username: Username,
    pub channel_id: ChannelId,
    pub comment: Option<String>,
    pub texture: Option<Vec<u8>>,
    pub comment_hash: Option<Sha1Hash>,
    pub texture_hash: Option<Sha1Hash>,
}

#[derive(Clone, Debug, Default)]
pub struct SessionData {
    pub muted_by_admin: bool,
    pub deafened_by_admin: bool,
    pub suppressed: bool,
    pub self_mute: bool,
    pub self_deaf: bool,
    pub priority_speaker: bool,
    pub recording: bool,
}

impl Storage {
    pub fn open(path_to_db_file: &str) -> Self {
        let db = sled::open(path_to_db_file).expect("Unable to open database");
        let users = db.open_tree(USER_TREE_NAME).unwrap();
        let channels = db.open_tree(CHANNEL_TREE_NAME).unwrap();

        let root_channel = bincode::serialize(&Channel {
            id: 0,
            name: "Root".to_string(),
            parent_id: None,
            linked_channels: vec![],
            description: None,
            description_hash: None,
            max_users: None,
            temporary: false,
            position: None,
        })
        .unwrap();
        channels
            .compare_and_swap(
                to_bytes(ROOT_CHANNEL_ID),
                Option::<&[u8]>::None,
                Some(root_channel),
            )
            .unwrap();

        Storage {
            users,
            channels,
            session_data: DashMap::new(),
            guests: DashMap::new(),
            connected_users: DashMap::new(),
            connected: Default::default(),
        }
    }

    pub fn add_guest(&self, guest: Guest) {
        let session_id = guest.session_id;
        self.guests.insert(session_id, guest);
        self.session_data.insert(session_id, SessionData::default());
        self.connected.fetch_add(1, Ordering::SeqCst);
    }

    pub fn add_connected_user(&self, user: User, session_id: SessionId) {
        self.connected_users
            .insert(session_id, (user.id, user.username));
        self.session_data.insert(session_id, SessionData::default());
        self.connected.fetch_add(1, Ordering::SeqCst);
    }

    pub fn get_channels(&self) -> Vec<Channel> {
        self.channels
            .iter()
            .values()
            .map(|channel| bincode::deserialize(&channel.unwrap()).unwrap())
            .collect()
    }

    pub fn get_guests(&self) -> Vec<Guest> {
        self.guests.iter().map(|el| el.value().clone()).collect()
    }

    pub fn get_connected_users(&self) -> Vec<(SessionId, User)> {
        let connected_users: Vec<(SessionId, UserId)> = self
            .connected_users
            .iter()
            .map(|el| (*el.key(), el.value().0))
            .collect();
        let mut users = Vec::with_capacity(connected_users.len());
        for (session_id, user_id) in connected_users {
            if let Ok(Some(bytes)) = self.users.get(&to_bytes(user_id)) {
                let user: User = bincode::deserialize(&bytes).unwrap();
                users.push((session_id, user));
            }
        }
        users
    }

    pub fn get_guest(&self, id: SessionId) -> Option<Guest> {
        self.guests.get(&id).map(|entry| entry.value().clone())
    }

    pub fn get_connected_user(&self, id: SessionId) -> Option<User> {
        if let Some(entry) = self.connected_users.get(&id) {
            self.get_user_by_id(entry.value().0)
        } else {
            None
        }
    }

    pub fn get_session_data(&self, id: SessionId) -> Option<SessionData> {
        self.session_data
            .get(&id)
            .map(|entry| entry.value().clone())
    }

    pub fn get_user_by_id(&self, id: UserId) -> Option<User> {
        if let Ok(Some(user)) = self.users.get(bincode::serialize(&id).unwrap()) {
            return bincode::deserialize(&user).unwrap();
        }
        None
    }

    pub fn get_user_by_username(&self, username: Username) -> Option<User> {
        self.users
            .iter()
            .filter_map(|value| value.ok())
            .find_map(|(_, user)| {
                let user: User = bincode::deserialize(&user).unwrap();
                if user.username == username {
                    Some(user)
                } else {
                    None
                }
            })
    }

    pub fn update_session_data(&self, id: SessionId, data: SessionData) {
        self.session_data.insert(id, data);
    }

    pub fn username_in_connected(&self, username: &str) -> bool {
        if self
            .guests
            .iter()
            .find(|entry| entry.value().username == username)
            .is_some()
        {
            true
        } else if self
            .connected_users
            .iter()
            .find(|entry| entry.value().1 == username)
            .is_some()
        {
            true
        } else {
            false
        }
    }

    pub fn watch_connected_count(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.connected)
    }

    pub fn remove_by_session_id(&self, id: SessionId) {
        self.connected_users.remove(&id);
        self.guests.remove(&id);
        self.session_data.remove(&id);
        self.connected.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Guest {
    pub fn new(username: String, session_id: SessionId, channel_id: ChannelId) -> Self {
        Guest {
            session_id,
            username,
            channel_id,
            comment: None,
            texture: None,
            comment_hash: None,
            texture_hash: None,
        }
    }
}

impl SessionData {
    fn new() -> Self {
        SessionData {
            muted_by_admin: false,
            deafened_by_admin: false,
            suppressed: false,
            self_mute: false,
            self_deaf: false,
            priority_speaker: false,
            recording: false,
        }
    }
}

fn to_bytes(number: u32) -> [u8; 4] {
    number.to_be_bytes()
}
