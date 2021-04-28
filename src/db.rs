use serde::{Deserialize, Serialize};

const USER_TREE_NAME: &[u8] = b"users";
const CHANNEL_TREE_NAME: &[u8] = b"channels";
const ROOT_CHANNEL_KEY: &[u8] = &0_u64.to_be_bytes();

pub struct Db {
    db: sled::Db,
    users: sled::Tree,
    channels: sled::Tree,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub channel_id: u32,
    pub is_connected: bool,
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
        }).unwrap();
        channels.compare_and_swap(
            ROOT_CHANNEL_KEY,
            Option::<&[u8]>::None,
            Some(root_channel))
            .unwrap().unwrap();

        Db {
            db,
            users,
            channels,
        }
    }

    pub async fn add_new_user(&self, user: User) {
        let id = self.users.len().to_be_bytes();

        self.users.insert(
            id,
            bincode::serialize(&user).unwrap(),
        ).unwrap();

        self.users.flush_async().await.unwrap();
    }

    pub fn get_channels(&self) -> Vec<Channel> {
        self.channels.iter().values()
            .map(|channel| bincode::deserialize(&channel.unwrap()).unwrap())
            .collect()
    }

    pub fn get_connected_users(&self) -> Vec<User> {
        self.users.iter().values()
            .map(|user| bincode::deserialize(&user.unwrap()).unwrap())
            .filter(|user: &User| user.is_connected)
            .collect()
    }
}
