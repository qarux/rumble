use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsStream};

use crate::client::{Client, Message, ResponseMessage};
use crate::connection::{Connection, ConnectionConfig};
use crate::db::Db;

pub struct Config {
    pub ip_address: IpAddr,
    pub port: u16,
    pub certificate: Certificate,
    pub private_key: PrivateKey,
    pub path_to_db_file: String,
}

type Clients = Arc<RwLock<HashMap<u32, Client>>>;

pub async fn run(config: Config) -> std::io::Result<()> {
    let db = Arc::new(Db::open(&config.path_to_db_file));

    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    tls_config
        .set_single_cert(vec![config.certificate], config.private_key)
        .expect("Invalid private key");

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(SocketAddr::new(config.ip_address, config.port)).await?;

    let clients = Arc::new(RwLock::new(HashMap::new()));
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let db = Arc::clone(&db);
        let clients = Arc::clone(&clients);

        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await;
            if let Ok(stream) = stream {
                process(db, TlsStream::from(stream), clients).await;
            }
        });
    }
}

async fn process(db: Arc<Db>, stream: TlsStream<TcpStream>, clients: Clients) {
    let connection_config = ConnectionConfig {
        max_bandwidth: 128000,
        welcome_text: "Welcome!".to_string(),
    };
    let connection = match Connection::setup_connection(db.clone(), stream, connection_config).await
    {
        Ok(connection) => connection,
        Err(_) => {
            eprintln!("Error establishing a connection");
            return;
        }
    };
    let session_id = connection.session_id;
    let (client, mut response_receiver) = Client::new(connection, db).await;

    {
        let mut clients = clients.write().await;
        for client in clients.values() {
            client.post_message(Message::UserConnected(session_id))
        }
        clients.insert(session_id, client);
    }

    loop {
        let message = match response_receiver.recv().await {
            Some(msg) => msg,
            None => return,
        };

        match message {
            ResponseMessage::Disconnected => {
                let mut clients = clients.write().await;
                clients.remove(&session_id);
                for client in clients.values() {
                    client.post_message(Message::UserDisconnected(session_id))
                }
                return;
            }
            ResponseMessage::Talking(audio_data) => {
                let clients = clients.read().await;
                for client in clients
                    .values()
                    .filter(|client| client.session_id != session_id)
                {
                    client.post_message(Message::UserTalking(audio_data.clone()));
                }
            }
        }
    }
}
