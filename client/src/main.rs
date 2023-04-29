mod auth;
mod msg_receiver;

use anyhow::{anyhow, bail, Result};
use aucpace::{AuCPaceClient, ServerMessage};
use clap::Parser;
use rand_core::OsRng;
use scrypt::password_hash::ParamsString;
use scrypt::{Params, Scrypt};
use serialport::{SerialPort, SerialPortType};
use sha3::Sha3_512;
use std::io::{Read, Write};
use std::sync::Mutex;
use std::thread::AccessError;
use std::time::Duration;
use std::{io, thread};

use crate::auth::{establish_key, register_user};
use crate::msg_receiver::MsgReceiver;
use shared::{Action, ActionToken, EncryptedMessage, Message, Response};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

const USART_BAUD: u32 = 28800;
const RECV_BUF_LEN: usize = 1024;
const K1: usize = 16;

type Client = AuCPaceClient<Sha3_512, Scrypt, OsRng, K1>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the USB port to open
    #[arg(long)]
    port: Option<String>,

    /// List USB ports on the system
    #[arg(long)]
    list_ports: bool,

    /// The maximum log level
    #[arg(long, default_value_t = tracing::Level::INFO)]
    log_level: tracing::Level,

    /// Perform registration before AuCPace
    #[arg(long)]
    register: bool,

    /// The Username to perform the exchange with
    #[arg(long, short)]
    username: String,

    // TODO: replace this with rpassword when stuff actually works
    /// The Password to perform the exchange with
    #[arg(long, short)]
    password: String,
}

fn main() -> Result<()> {
    let args = Args::try_parse()?;

    // setup the logger
    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_max_level(args.log_level)
        .with_writer(io::stderr)
        .init();

    debug!("args={args:?}");

    // list the ports if the user asks for it
    if args.list_ports {
        let mut ports = serialport::available_ports()?;
        ports.retain(|port| matches!(port.port_type, SerialPortType::UsbPort(_)));
        println!("Found the following USB ports:");
        for port in ports {
            println!("{}", port.port_name);
        }

        return Ok(());
    }

    // open the serial port connection
    let port_name = args
        .port
        .ok_or_else(|| anyhow!("Must supply a USB port."))?;
    let serial = Mutex::new({
        serialport::new(port_name, USART_BAUD)
            .timeout(Duration::from_secs(10))
            .open()?
    });
    let mut receiver = MsgReceiver::new(&serial);
    info!("Opened serial port connection.");

    // start the client
    let mut base_client: AuCPaceClient<Sha3_512, Scrypt, OsRng, K1> = AuCPaceClient::new(OsRng);
    let user = args.username.as_bytes();
    let pass = args.password.as_bytes();
    if args.register {
        register_user(&serial, &mut base_client, user, pass)?;
    }

    let key = establish_key(&serial, &mut receiver, &mut base_client, user, pass)?;
    info!("Established strong shared key.");

    // read an action token
    let enc_message: EncryptedMessage = receiver.recv_msg()?;
    let mut buf = [0u8; 512];
    let mut serialised = enc_message
        .decrypt_into(&key, &mut buf)
        .map_err(|e| anyhow!(e))?;
    let msg: Message = postcard::from_bytes(serialised)?;
    let Message::Token(at) = msg else {
        bail!("Received invalid message - expected Token");
    };

    // read the metadata
    let reply = Message::ActionRequest {
        action: Action::ReadSectorMetadata,
        token: at,
    };
    let mut serialised = postcard::to_stdvec(&reply)?;
    let enc_message =
        EncryptedMessage::encrypt(&mut serialised, &key, &mut OsRng).map_err(|e| anyhow!(e))?;
    let enc_message_ser = postcard::to_stdvec_cobs(&enc_message)?;
    {
        let mut tx = serial.lock().unwrap();
        tx.write_all(&enc_message_ser)?;
    }

    // read the metadata
    let enc_message: EncryptedMessage = receiver.recv_msg()?;
    let mut buf = [0u8; 512];
    let mut serialised = enc_message
        .decrypt_into(&key, &mut buf)
        .map_err(|e| anyhow!(e))?;
    let msg: Message = postcard::from_bytes(serialised)?;
    let Message::ActionResponse {
        response: Response::SectorMetadata { populated }
    } = msg else {
        bail!("Received invalid message - expected ActionResponse {{ response: SectorMetadata }}");
    };

    eprintln!("populated = {populated:02X?}");

    Ok(())
}
