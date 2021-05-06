use std::fs::File;
use std::io::BufReader;

use clap::{App, Arg};
use tokio::runtime::Builder;
use tokio_rustls::rustls::{Certificate, internal::pemfile, PrivateKey};

mod server;
mod proto;
mod protocol;
mod connection;
mod db;
mod client;

fn main() {
    let matches = App::new("Rumble")
        .version("0.0.1")
        .about("Rumble is a mumble server written in Rust.")
        .arg(Arg::with_name("ip")
            .long("ip")
            .default_value("0.0.0.0")
            .takes_value(true)
            .help("Specific IP or hostname to bind to"))
        .arg(Arg::with_name("port")
            .long("port")
            .short("p")
            .default_value("64738")
            .takes_value(true)
            .help("Port to use"))
        .arg(Arg::with_name("certificate")
            .long("cert_file")
            .short("c")
            .takes_value(true)
            .required(true)
            .help("Path to a ssl certificate"))
        .arg(Arg::with_name("private key")
            .long("private_key")
            .short("k")
            .takes_value(true)
            .required(true)
            .help("Path to a ssl keyfile"))
        .get_matches();

    let ip = matches.value_of("ip").unwrap();
    let port = matches.value_of("port").unwrap();
    let cert_file = matches.value_of("certificate").unwrap();
    let keyfile = matches.value_of("private key").unwrap();
    let path = "db/".to_string();

    let config = server::Config {
        ip_address: ip.parse().unwrap(),
        port: port.parse().unwrap(),
        certificate: read_certificate(cert_file),
        private_key: read_private_key(keyfile),
        path_to_db_file: path,
    };

    let tokio_rt = Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio_rt.block_on(async {
        server::run(config).await.unwrap();
    });
}

fn read_certificate(path: &str) -> Certificate {
    let mut file = BufReader::new(File::open(path).unwrap());
    pemfile::certs(&mut file).unwrap().remove(0)
}

fn read_private_key(path: &str) -> PrivateKey {
    let mut file = BufReader::new(File::open(path).unwrap());
    pemfile::pkcs8_private_keys(&mut file).unwrap().remove(0)
}