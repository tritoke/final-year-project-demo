use anyhow::{anyhow, Result};
use aucpace::{Client, ServerMessage};
use clap::Parser;
use scrypt::password_hash::ParamsString;
use scrypt::{Params, Scrypt};
use serialport::{SerialPort, SerialPortType};
use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{io, thread};

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

const USART_BAUD: u32 = 28800;
const RECV_BUF_LEN: usize = 1024;
const K1: usize = 16;

#[cfg(feature = "static_ssid")]
const SSID: [u8; 32] = [
    60, 173, 56, 252, 74, 141, 171, 146, 102, 169, 149, 169, 158, 106, 87, 232, 220, 141, 251, 73,
    39, 130, 105, 184, 93, 87, 195, 23, 246, 158, 85, 226,
];

/// function like macro to wrap sending data over the serial port, returns the number of bytes sent
macro_rules! send {
    ($serial_mtx:ident, $msg:ident) => {{
        let serialised = postcard::to_stdvec_cobs(&$msg).expect("Failed to serialise message");
        trace!("Sending {} byte long message - {serialised:02X?}", serialised.len());
        $serial_mtx
            .lock()
            .expect("Failed to acquire serial port mutex")
            .write_all(&serialised)
            .expect("Failed to write message to serial");
        thread::sleep(Duration::from_millis(10));
        serialised.len()
    }};
}

/// function like macro to wrap receiving data over the serial port
macro_rules! recv {
    ($recvr:ident) => {
        loop {
            let parsed = $recvr.recv_msg();
            match parsed {
                Ok(msg) => {
                    debug!("Parsed message - {msg:?}");
                    break msg;
                }
                Err(e) => {
                    error!("Failed to parse message - {e:?}");
                }
            };
        }
    };
}

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

    /// Skip perform registration before AuCPace
    #[arg(long)]
    skip_register: bool,

    /// The Username to perform the exchange with
    #[arg(long, short)]
    username: String,

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
            .timeout(Duration::from_millis(500))
            .open()?
    });
    let mut receiver = MsgReceiver::new(&serial);
    info!("Opened serial port connection.");

    // start the client
    let mut base_client = Client::new(rand_core::OsRng);
    let mut bytes_sent = 0;

    let user = args.username.as_str();
    let pass = args.password.as_str();
    if !args.skip_register {
        #[cfg(not(feature = "strong"))]
        let message = base_client
            .register_alloc(user.as_bytes(), pass, Params::recommended(), Scrypt)
            .map_err(|e| anyhow!(e))?;

        #[cfg(feature = "strong")]
        let message = base_client
            .register_alloc_strong(user.as_bytes(), pass, Params::recommended(), Scrypt)
            .map_err(|e| anyhow!(e))?;

        let _ = send!(serial, message);
        info!(
            "Registered as {user}:{pass} for {}",
            if cfg!(feature = "strong") {
                "Strong AuCPace"
            } else {
                "AuCPace"
            }
        );
    }

    info!("Starting AuCPace");
    let start = Instant::now();
    // ===== SSID Establishment =====
    #[cfg(feature = "static_ssid")]
    let client = {
        let client = base_client.begin_prestablished_ssid(SSID).unwrap();
        info!("Began from static SSID={:02X?}", SSID);
        client
    };

    #[cfg(not(feature = "static_ssid"))]
    let client = {
        let (client, message) = base_client.begin();
        bytes_sent += send!(serial, message);

        let server_message = recv!(receiver);
        let client = if let ServerMessage::Nonce(server_nonce) = server_message {
            client.agree_ssid(server_nonce)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };
        info!("Agreed on SSID");
        client
    };

    // ===== Augmentation Layer =====
    #[cfg(not(feature = "strong"))]
    let (client, message) = {
        info!("Sending message: Username");
        client.start_augmentation(user.as_bytes(), pass.as_bytes())
    };
    #[cfg(feature = "strong")]
    let (client, message) = {
        info!("Sending message: Strong Username");
        client.start_augmentation_strong(user.as_bytes(), pass.as_bytes(), &mut rand_core::OsRng)
    };
    bytes_sent += send!(serial, message);

    let mut server_message = recv!(receiver);
    #[cfg(not(feature = "strong"))]
    let client = if let ServerMessage::AugmentationInfo {
        x_pub,
        salt,
        pbkdf_params,
        ..
    } = server_message
    {
        info!("Received Augmentation info");
        let params = parse_params(pbkdf_params)?;
        client
            .generate_cpace_alloc(x_pub, &salt, params, Scrypt)
            .expect("Failed to generate CPace step data")
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    #[cfg(feature = "strong")]
    let client = if let ServerMessage::StrongAugmentationInfo {
        x_pub,
        blinded_salt,
        pbkdf_params,
        ..
    } = server_message
    {
        info!("Received Strong Augmentation info");
        let params = parse_params(pbkdf_params)?;
        client
            .generate_cpace_alloc(x_pub, blinded_salt, params, Scrypt)
            .expect("Failed to generate CPace step data")
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== CPace substep =====
    let ci = "Server-USART2-Client-SerialPort";
    let (client, message) = client.generate_public_key(ci, &mut rand_core::OsRng);
    bytes_sent += send!(serial, message);
    info!("Sent PublicKey");

    server_message = recv!(receiver);
    let ServerMessage::PublicKey(server_pubkey) = server_message else {
        panic!("Received invalid server message {:?}", server_message);
    };
    let key = if cfg!(feature = "implicit") {
        client.implicit_auth(server_pubkey)
            .map_err(|e| anyhow!(e))?
    } else {
        let (client, message) = client.receive_server_pubkey(server_pubkey)
            .map_err(|e| anyhow!(e))?;

        // ===== Explicit Mutual Auth =====
        bytes_sent += send!(serial, message);
        info!("Sent Authenticator");

        server_message = recv!(receiver);
        if let ServerMessage::Authenticator(server_authenticator) = server_message {
            client
                .receive_server_authenticator(server_authenticator)
                .expect("Failed Explicit Mutual Authentication")
        } else {
            panic!("Received invalid server message {:?}", server_message);
        }
    };

    info!("Derived final key: {:02X?}", key.as_slice());
    info!("Total bytes sent: {}", bytes_sent);
    info!(
        "Derived final key in {}ms",
        Instant::now().duration_since(start).as_millis()
    );

    Ok(())
}

struct MsgReceiver<'mtx> {
    buf: [u8; RECV_BUF_LEN],
    idx: usize,
    mtx: &'mtx Mutex<Box<dyn SerialPort>>,
    reset_pos: Option<usize>,
}

impl<'mtx> MsgReceiver<'mtx> {
    fn new(mtx: &'mtx Mutex<Box<dyn SerialPort>>) -> Self {
        Self {
            buf: [0u8; 1024],
            idx: 0,
            mtx,
            reset_pos: None,
        }
    }

    fn recv_msg(&mut self) -> postcard::Result<ServerMessage<'_, K1>> {
        // reset the state
        // copy all the data we read after the 0 byte to the start of the self.buffer
        if let Some(zi) = self.reset_pos {
            self.buf.copy_within(zi + 1..self.idx, 0);
            self.idx = self.idx.saturating_sub(zi + 1);
            self.reset_pos = None;
        }

        // acquire a handle to the serial port
        let mut serial = self
            .mtx
            .lock()
            .expect("Failed to acquire lock for serial port.");

        loop {
            // read as much as we can off the wire
            let count = serial
                .read(&mut self.buf[self.idx..])
                .expect("Failed to read from serial port.");
            let zero_idx = if count == 0 {
                continue;
            } else {
                // log that we managed to read some data
                trace!(
                    "Read {} bytes - {:02X?}",
                    count,
                    &self.buf[self.idx..self.idx + count]
                );

                // update state
                self.idx += count;

                // calculate the index of zero in the self.buffer
                // it is tempting to optimise this to just what is read but more than one packet can
                // be read at once so the whole buffer needs to be searched to allow for this behaviour
                let zero_idx = self.buf[..self.idx].iter().position(|x| *x == 0);

                zero_idx
            };

            let Some(zi) = zero_idx else {
                if self.idx == RECV_BUF_LEN {
                    self.idx = 0;
                    warn!("Weird state encountered - filled entire self.buffer without finding message.");
                }

                continue;
            };

            self.reset_pos = Some(zi);
            // parse the result
            break postcard::from_bytes_cobs::<ServerMessage<K1>>(&mut self.buf[..=zi]);
        }
    }
}

fn parse_params(ps: ParamsString) -> Result<Params> {
    const MSG: &str = "Missing parameter in ParamsString";
    let ln = ps.get_str("ln").ok_or_else(|| anyhow!(MSG))?.parse()?;
    let r = ps.get_str("r").ok_or_else(|| anyhow!(MSG))?.parse()?;
    let p = ps.get_str("p").ok_or_else(|| anyhow!(MSG))?.parse()?;
    let len = Params::RECOMMENDED_LEN;

    Ok(Params::new(ln, r, p, len)?)
}
