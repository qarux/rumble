pub struct Db {
    db: sled::Db,
    users: sled::Tree,
    channels: sled::Tree,
}

impl Db {
    pub fn open(path_to_db_file: &str) -> Self {
        let db = sled::open(path_to_db_file).expect("Unable to open database");
        let users = db.open_tree(USER_TREE_NAME).unwrap();
        let channels = db.open_tree(CHANNEL_TREE_NAME).unwrap();

        Db {
            db,
            users,
            channels,
        }
    }
}
