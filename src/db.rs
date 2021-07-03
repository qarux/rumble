use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::RwLock;

const ROOT_CHANNEL_ID: u32 = 0;
const USER_TREE_NAME: &[u8] = b"users";
const CHANNEL_TREE_NAME: &[u8] = b"channels";

type SessionId = u32;

pub struct Db {
    db: sled::Db,
    users: sled::Tree,
    channels: sled::Tree,
    connected_users: RwLock<HashMap<SessionId, User>>,
    next_session_id: AtomicU32,
}

#[derive(Clone)]
pub struct User {
    pub id: Option<u32>,
    pub username: String,
    pub channel_id: u32,
    pub session_id: SessionId,
}

#[derive(Serialize, Deserialize)]
struct PersistentUserData {
    id: u32,
    username: String,
    channel_id: u32,
}

#[derive(Serialize, Deserialize)]
pub struct Channel {
    pub id: u32,
    pub name: String,
}

impl Db {
    pub fn open(path_to_db_file: &str) -> Self {
        let db = sled::open(path_to_db_file).expect("Unable to open database");
        let users = db.open_tree(USER_TREE_NAME).unwrap();
        let channels = db.open_tree(CHANNEL_TREE_NAME).unwrap();

        let root_channel = bincode::serialize(&Channel {
            id: 0,
            name: "Root".to_string(),
        })
        .unwrap();
        channels
            .compare_and_swap(
                ROOT_CHANNEL_ID.to_be_bytes(),
                Option::<&[u8]>::None,
                Some(root_channel),
            )
            .unwrap();

        Db {
            db,
            users,
            channels,
            connected_users: RwLock::new(HashMap::new()),
            next_session_id: AtomicU32::new(0),
        }
    }

    pub async fn add_new_user(&self, username: String) -> u32 {
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let mut connected_users = self.connected_users.write().await;
        connected_users.insert(
            session_id,
            User {
                id: None,
                username,
                channel_id: ROOT_CHANNEL_ID,
                session_id,
            },
        );
        session_id
    }

    pub async fn get_channels(&self) -> Vec<Channel> {
        self.channels
            .iter()
            .values()
            .map(|channel| bincode::deserialize(&channel.unwrap()).unwrap())
            .collect()
    }

    pub async fn get_connected_users(&self) -> Vec<User> {
        let users = self.connected_users.read().await;
        users.values().cloned().collect()
    }

    pub async fn get_user_by_session_id(&self, session_id: u32) -> Option<User> {
        let connected_users = self.connected_users.read().await;
        if let Some(user) = connected_users.get(&session_id) {
            return Some(user.clone());
        }
        None
    }

    pub async fn remove_connected_user(&self, session_id: u32) {
        let mut connected_users = self.connected_users.write().await;
        connected_users.remove(&session_id);
    }
}
