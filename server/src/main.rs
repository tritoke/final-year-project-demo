#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

mod database;
mod msg_receiver;
mod storage;

use aucpace::{AuCPaceServer, ClientMessage};
use core::fmt::Write as _;
use database::SingleUserDatabase;
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::interrupt;
use embassy_stm32::time::Hertz;
use embassy_stm32::usart::{Config, Uart};
use embassy_time::{Delay, Instant};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use {defmt_rtt as _, panic_probe as _};

use crate::msg_receiver::MsgReceiver;
use crate::storage::{Entry, Storage};
use aucpace::PartialAugDatabase;
use aucpace::StrongDatabase;
use embassy_stm32::adc::Adc;
use embassy_stm32::flash::Flash;

// AuCPace nonce-size constant
const K1: usize = 16;

/// function like macro to wrap sending data over USART2, returns the number of bytes sent
macro_rules! send {
    ($tx:ident, $buf:ident, $msg:ident) => {{
        let serialised = postcard::to_slice_cobs(&$msg, &mut $buf).unwrap();
        unwrap!($tx.write(&serialised).await);
    }};
}

/// function like macro to wrap receiving data over USART2
macro_rules! recv {
    ($recvr:ident) => {
        loop {
            let parsed = $recvr.recv_msg().await;
            match parsed {
                Ok(msg) => {
                    trace!("Parsed message - {:?}", Debug2Format(&msg));
                    break msg;
                }
                Err(e) => {
                    error!("Failed to parse message - {:?}", Debug2Format(&e));
                }
            };
        }
    };
}

#[cfg(not(test))]
#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    // make clock go brrr
    let mut rcc_config: embassy_stm32::rcc::Config = Default::default();
    rcc_config.sys_ck = Some(Hertz::mhz(84));
    let mut board_config: embassy_stm32::Config = Default::default();
    board_config.rcc = rcc_config;
    let p = embassy_stm32::init(board_config);
    debug!("Initialised peripherals.");

    // configure USART2 which goes over the USB port on this board
    let mut config = Config::default();
    config.baudrate = 28800;
    let irq = interrupt::take!(USART2);
    let (mut tx, rx) =
        Uart::new(p.USART2, p.PA3, p.PA2, irq, p.DMA1_CH6, p.DMA1_CH5, config).split();
    debug!("Configured USART2.");

    // configure the temperature sensor
    let mut delay = Delay;
    let mut adc = Adc::new(p.ADC1, &mut delay);
    let mut temp_channel = adc.enable_temperature();

    // configure the RNG, kind of insecure but this is just a demo and I don't have real entropy
    let now = Instant::now().as_micros();
    // this needs converting but I'm just using it for entropy
    let temp = adc.read_internal(&mut temp_channel);
    let seed = now << 16 | temp as u64;
    let server_rng = ChaCha8Rng::seed_from_u64(seed);
    debug!("Seeded RNG - seed = {}", seed);

    // create our AuCPace server
    let mut base_server: AuCPaceServer<sha2::Sha512, _, K1> = AuCPaceServer::new(server_rng);
    let mut database: SingleUserDatabase<100> = SingleUserDatabase::default();
    debug!("Created the Strong AuCPace Server and the Single User Database");

    // create something to receive messages
    let mut buf = [0u8; 1024];
    let mut receiver = MsgReceiver::new(rx);
    debug!("Receiver and buffers set up");

    // wait for a user to register themselves
    debug!("Waiting for a registration packet.");
    let user = loop {
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
                break username;
            }
        }
    };

    let (priv_key, pub_key) = base_server.generate_long_term_keypair();
    // it is fine to unwrap here because we have already registered
    // a verifier for the user with store_verifier
    database
        .store_long_term_keypair(user, priv_key, pub_key)
        .unwrap();
    debug!("Stored a long term keypair for {:a}", user);

    let _key = loop {
        let start = Instant::now();
        let mut session_rng = ChaCha8Rng::seed_from_u64(start.as_micros());
        debug!("Seeded Session RNG - seed = {}", start.as_micros());

        // now do a key-exchange
        debug!("Beginning AuCPace protocol");

        // ===== SSID Establishment =====
        let server = {
            let (server, message) = base_server.begin();

            let client_message: ClientMessage<K1> = recv!(receiver);
            let server = if let ClientMessage::Nonce(client_nonce) = client_message {
                server.agree_ssid(client_nonce)
            } else {
                error!(
                    "Received invalid client message {:?} - restarting negotiation",
                    defmt::Debug2Format(&client_message),
                );
                continue;
            };
            debug!("Received Client Nonce");

            // now that we have received the client nonce, send our nonce back
            send!(tx, buf, message);
            info!("Sent Nonce");

            server
        };

        // ===== Augmentation Layer =====
        let mut client_message = recv!(receiver);
        let (server, message) =
            if let ClientMessage::StrongUsername { username, blinded } = client_message {
                let ret = server.generate_client_info_partial_strong(
                    username,
                    blinded,
                    &database,
                    &mut session_rng,
                );
                match ret {
                    Ok(inner) => inner,
                    Err(e) => {
                        error!(
                            "Receiving client Public Key returned an error {:?}",
                            Debug2Format(&e)
                        );
                        continue;
                    }
                }
            } else {
                error!(
                    "Received invalid client message {:?} - restarting negotiation",
                    Debug2Format(&client_message),
                );
                continue;
            };

        send!(tx, buf, message);
        debug!("Received Client Username and Blinded Point");
        debug!("Sent Strong Augmentation Info");

        // ===== CPace substep =====
        let ci = "Server-USART2-Client-SerialPort";
        let (server, message) = server.generate_public_key(ci);
        send!(tx, buf, message);
        debug!("Sent PublicKey");

        client_message = recv!(receiver);
        let ClientMessage::PublicKey(client_pubkey) = client_message else {
            error!("Received invalid client message {:?}", Debug2Format(&client_message));
            continue;
        };

        let server = match server.receive_client_pubkey(client_pubkey) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Receiving client Public Key returned an error {:?}",
                    Debug2Format(&e)
                );
                continue;
            }
        };
        debug!("Received Client PublicKey");

        // ===== Explicit Mutual Authentication =====
        client_message = recv!(receiver);
        let (key, message) = if let ClientMessage::Authenticator(ca) = client_message {
            match server.receive_client_authenticator(ca) {
                Ok(inner) => inner,
                Err(e) => {
                    error!(
                        "Client failed the Explicit Mutual Authentication check - {:?}",
                        Debug2Format(&e)
                    );
                    continue;
                }
            }
        } else {
            error!(
                "Received invalid client message {:?}",
                Debug2Format(&client_message)
            );
            continue;
        };
        send!(tx, buf, message);
        debug!("Sent Authenticator");

        break key;
    };

    debug!("Established strong shared key");

    info!("Setting up flash storage");
    let mut storage = unwrap!(Storage::new(Flash::new(p.FLASH)));

    info!("storage.no_entries() = {}", storage.no_entries());

    let e = Entry {
        pwd_data: [b'A'; 128],
        metadata: [b'B'; 128],
    };
    info!("Writing a new entry");
    unwrap!(storage.add_entry(e));
    info!("storage.no_entries() = {}", storage.no_entries());

    info!("Getting last entry");
    let entry = unwrap!(storage.get_entry(0));
    debug!("e = {}", e);
    debug!("entry = {}", entry);
    debug!("entry == e: {}", entry == e);
    defmt::assert_eq!(e, entry);
    info!("Getting entry succeeded");

    info!("Deleting last entry");
    unwrap!(storage.del_entry(0));
    info!("storage.no_entries() = {}", storage.no_entries());

    loop {}
}

#[cfg(test)]
#[defmt_test::tests]
pub mod tests {
    use crate::storage::Entry;
    use defmt::{assert_eq, debug};

    #[test]
    fn test_entry_serialize() {
        let entry = Entry {
            pwd_data: [0x69; 128],
            metadata: [0x42; 128],
        };

        let ser = entry.serialize();
        let mut correct = [0x69u8; 256];
        correct[128..].fill(0x42);

        assert_eq!(ser, correct);
    }

    #[test]
    fn test_entry_deserialize() {
        let mut ser = [0xABu8; 256];
        ser[128..].fill(0xCD);

        let deser = Entry::deserialize(ser);
        let correct = Entry {
            pwd_data: [0xAB; 128],
            metadata: [0xCD; 128],
        };

        assert_eq!(deser.pwd_data, correct.pwd_data);
        assert_eq!(deser.metadata, correct.metadata);
    }

    #[test]
    fn test_entry_roundtrip_serialization() {
        let entry = Entry {
            pwd_data: [0x69; 128],
            metadata: [0x42; 128],
        };

        let ser = entry.serialize();
        let deser = Entry::deserialize(ser);

        assert_eq!(entry.pwd_data, deser.pwd_data);
        assert_eq!(entry.metadata, deser.metadata);
    }
}
