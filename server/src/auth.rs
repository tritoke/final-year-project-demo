use crate::{database::SingleUserDatabase, msg_receiver::MsgReceiver, K1};
use aucpace::{AuCPaceServer, ClientMessage, StrongDatabase};
use chacha20poly1305::Key;
use defmt::{debug, error, info, trace, unwrap};
use embassy_stm32::peripherals::{DMA1_CH6, USART2};
use embassy_stm32::usart::UartTx;
use rand_chacha::ChaCha8Rng;
use rand_core::CryptoRngCore;
use sha3::Sha3_512;

/// function like macro to wrap sending data over USART2, returns the number of bytes sent
macro_rules! send {
    ($tx:ident, $buf:ident, $msg:ident) => {{
        let serialised = postcard::to_slice_cobs(&$msg, $buf).unwrap();
        unwrap!($tx.write(&serialised).await);
    }};
}

/// function like macro to wrap receiving data over USART2
macro_rules! recv {
    ($recvr:ident) => {
        loop {
            let parsed = $recvr.recv_msg::<ClientMessage<K1>>().await;
            match parsed {
                Ok(msg) => {
                    trace!("Parsed message - {:?}", defmt::Debug2Format(&msg));
                    break msg;
                }
                Err(e) => {
                    error!("Failed to parse message - {:?}", defmt::Debug2Format(&e));
                }
            };
        }
    };
}

pub async fn register_user(database: &mut SingleUserDatabase, receiver: &mut MsgReceiver<'_>) {
    // wait for a user to register themselves
    loop {
        debug!("Waiting for a registration packet.");
        let msg = recv!(receiver);

        if let ClientMessage::StrongRegistration {
            username,
            secret_exponent,
            params,
            verifier,
        } = msg
        {
            if username.len() > 100 {
                error!("Attempted to register with a username thats too long.");
            } else {
                database.store_verifier_strong(username, None, verifier, secret_exponent, params);
                info!("Registered {:a} for Strong AuCPace", username);
                break;
            }
        }
    }
}

pub async fn establish_key(
    base_server: &mut AuCPaceServer<Sha3_512, ChaCha8Rng, K1>,
    database: &SingleUserDatabase,
    session_rng: &mut impl CryptoRngCore,
    receiver: &mut MsgReceiver<'_>,
    tx: &mut UartTx<'_, USART2, DMA1_CH6>,
    buf: &mut [u8],
) -> Option<chacha20poly1305::Key> {
    // ===== SSID Establishment =====
    debug!("Waiting for client Nonce");
    let ClientMessage::Nonce(client_nonce) = recv!(receiver) else {
        return None;
    };
    debug!("Received Client Nonce");

    let (server, message) = base_server.begin();
    send!(tx, buf, message);
    debug!("Sent Nonce");

    let server = server.agree_ssid(client_nonce);

    // ===== Augmentation Layer =====
    let ClientMessage::StrongUsername { username, blinded } = recv!(receiver) else {
        return None;
    };
    debug!("Received Client Username and Blinded Point");

    let (server, message) = server
        .generate_client_info_strong(username, blinded, database, session_rng)
        .ok()?;
    send!(tx, buf, message);
    debug!("Sent Strong Augmentation Info");

    // ===== CPace substep =====
    let ci = "Server-USART2-Client-SerialPort";
    let (server, message) = server.generate_public_key(ci);
    send!(tx, buf, message);
    debug!("Sent PublicKey");

    let ClientMessage::PublicKey(client_pubkey) = recv!(receiver) else {
        return None;
    };

    let server = server.receive_client_pubkey(client_pubkey).ok()?;
    debug!("Received Client PublicKey");

    // ===== Explicit Mutual Authentication =====
    let ClientMessage::Authenticator(ca) = recv!(receiver) else {
        return None;
    };
    let (key, message) = server.receive_client_authenticator(ca).ok()?;
    send!(tx, buf, message);
    debug!("Sent Authenticator");

    // take the first 16 bytes of the hash as the key
    Some(*Key::from_slice(&key.as_slice()[..32]))
}
