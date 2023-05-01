use crate::msg_receiver::MsgReceiver;
use crate::Client;
use anyhow::{anyhow, bail, Result};
use aucpace::{AuCPaceClient, ServerMessage};
use chacha20poly1305::Key;
use rand_core::OsRng;
use scrypt::password_hash::ParamsString;
use scrypt::{Params, Scrypt};
use serialport::SerialPort;
use sha3::Sha3_512;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// function like macro to wrap sending data over the serial port, returns the number of bytes sent
macro_rules! send {
    ($serial:expr, $msg:ident) => {{
        let serialised = postcard::to_stdvec_cobs(&$msg).expect("Failed to serialise message");
        trace!(
            "Sending {} byte long message - {serialised:02X?}",
            serialised.len()
        );
        $serial
            .write_all(&serialised)
            .expect("Failed to write message to serial");
        thread::sleep(Duration::from_millis(10));
    }};
}

pub fn register_user(
    receiver: &mut MsgReceiver,
    base_client: &mut Client,
    user: &[u8],
    pass: &[u8],
) -> Result<()> {
    let message = base_client
        .register_alloc_strong(user, pass, Params::recommended(), Scrypt)
        .map_err(|e| anyhow!(e))?;

    send!(receiver.serial_mut(), message);
    info!(
        "Registered {} with StrongAuCPace",
        String::from_utf8_lossy(user)
    );

    Ok(())
}

pub fn establish_key(
    receiver: &mut MsgReceiver,
    base_client: &mut Client,
    user: &[u8],
    pass: &[u8],
) -> Result<Key> {
    info!("Starting StrongAuCPace");
    // ===== SSID Establishment =====
    let (client, message) = base_client.begin();
    send!(receiver.serial_mut(), message);

    let mut server_message = receiver.recv_msg()?;
    let ServerMessage::Nonce(server_nonce) = server_message else {
        bail!("Received invalid server message {:?}", server_message);
    };
    let client = client.agree_ssid(server_nonce);
    info!("Agreed on SSID");

    // ===== Augmentation Layer =====
    let (client, message) = client.start_augmentation_strong(user, pass, &mut OsRng);
    send!(receiver.serial_mut(), message);
    info!("Sent message: Strong Username");

    server_message = receiver.recv_msg()?;
    let ServerMessage::StrongAugmentationInfo {
        x_pub,
        blinded_salt,
        pbkdf_params,
        ..
    } = server_message else {
        bail!("Received invalid server message {:?}", server_message);
    };
    info!("Received Strong Augmentation info");

    let params = parse_params(pbkdf_params)?;
    let client = client
        .generate_cpace_alloc(x_pub, blinded_salt, params, Scrypt)
        .map_err(|e| anyhow!(e))?;

    // ===== CPace substep =====
    let ci = "Server-USART2-Client-SerialPort";
    let (client, message) = client.generate_public_key(ci, &mut OsRng);
    send!(receiver.serial_mut(), message);
    info!("Sent PublicKey");

    server_message = receiver.recv_msg()?;
    let ServerMessage::PublicKey(server_pubkey) = server_message else {
        bail!("Received invalid server message {:?}", server_message);
    };
    info!("Received Server Public Key");

    let (client, message) = client
        .receive_server_pubkey(server_pubkey)
        .map_err(|e| anyhow!(e))?;

    // ===== Explicit Mutual Auth =====
    send!(receiver.serial_mut(), message);
    info!("Sent Authenticator");

    server_message = receiver.recv_msg()?;
    let ServerMessage::Authenticator(server_authenticator) = server_message else {
        bail!("Received invalid server message {:?}", server_message);
    };

    let key = client
        .receive_server_authenticator(server_authenticator)
        .map_err(|e| anyhow!(e))?;
    Ok(Key::from_slice(&key.as_slice()[..32]).clone())
}

fn parse_params(ps: ParamsString) -> Result<Params> {
    const MSG: &str = "Missing parameter in ParamsString";
    let ln = ps.get_str("ln").ok_or_else(|| anyhow!(MSG))?.parse()?;
    let r = ps.get_str("r").ok_or_else(|| anyhow!(MSG))?.parse()?;
    let p = ps.get_str("p").ok_or_else(|| anyhow!(MSG))?.parse()?;
    let len = Params::RECOMMENDED_LEN;

    Ok(Params::new(ln, r, p, len)?)
}
