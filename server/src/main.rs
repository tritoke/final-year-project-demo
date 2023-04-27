#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

mod auth;
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
use embassy_stm32::usart::{Config, Uart, UartTx};
use embassy_time::{Delay, Instant};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use {defmt_rtt as _, panic_probe as _};

use crate::msg_receiver::MsgReceiver;
use crate::storage::{Entry, Storage};
use aucpace::StrongDatabase;
use curve25519_dalek::digest;
use embassy_stm32::adc::{Adc, Temperature};
use embassy_stm32::flash::{Flash, MAX_ERASE_SIZE};
use embassy_stm32::pac::FLASH_SIZE;
use embassy_stm32::peripherals::{ADC1, DMA1_CH6, USART2};
use sha2::digest::Output;
use sha2::Sha512;

// AuCPace nonce-size constant
const K1: usize = 16;

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
    let mut seed_generator = SeedGenerator::new(adc);
    debug!("Configured ADC.");

    let mut storage = unwrap!(Storage::new(Flash::new(p.FLASH)));
    debug!("Set up storage: metadata = {}", storage.metadata);

    // configure the RNG, kind of insecure but this is just a demo and I don't have real entropy
    let now = Instant::now().as_ticks();
    // this needs converting but I'm just using it for entropy
    let seed = seed_generator.gen_seed();
    let server_rng = ChaCha8Rng::seed_from_u64(seed);
    debug!("Seeded RNG - seed = {}", seed);

    // create our AuCPace server
    let mut base_server: AuCPaceServer<sha2::Sha512, _, K1> = AuCPaceServer::new(server_rng);
    let mut database = unwrap!(storage.retrieve_database());
    debug!("Created the Strong AuCPace Server and the retrieved the Single User Database");

    // create something to receive messages
    let mut buf = [0u8; 1024];
    let mut receiver = MsgReceiver::new(rx);
    debug!("Receiver and buffers set up");

    if !database.is_populated() {
        register_user(&mut database, &mut receiver, &mut tx, &mut buf);
    }

    let key = establish_key(
        &mut base_server,
        &database,
        &mut seed_generator,
        &mut receiver,
        &mut tx,
        &mut buf,
    );
    debug!("Established strong shared key");

    loop {}
}

async fn register_user(
    database: &mut SingleUserDatabase,
    receiver: &mut MsgReceiver<'_>,
    tx: &mut UartTx<'_, USART2, DMA1_CH6>,
    buf: &mut [u8],
) {
    // wait for a user to register themselves
    let user = loop {
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
                break username;
            }
        }
    };
}

async fn establish_key(
    base_server: &mut AuCPaceServer<Sha512, ChaCha8Rng, K1>,
    database: &SingleUserDatabase,
    seed_generator: &mut SeedGenerator<'_>,
    receiver: &mut MsgReceiver<'_>,
    tx: &mut UartTx<'_, USART2, DMA1_CH6>,
    buf: &mut [u8],
) -> Output<Sha512> {
    loop {
        let seed = seed_generator.gen_seed();
        let mut session_rng = ChaCha8Rng::seed_from_u64(seed);
        debug!("Seeded Session RNG - seed = {}", seed);

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
        let (server, message) = if let ClientMessage::StrongUsername { username, blinded } =
            client_message
        {
            match server.generate_client_info_strong(username, blinded, database, &mut session_rng)
            {
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
    }
}

// an attempt at generating some entropy / non repeating values
struct SeedGenerator<'adc> {
    adc: Adc<'adc, ADC1>,
    temp_channel: Temperature,
}

impl<'adc> SeedGenerator<'adc> {
    fn new(mut adc: Adc<'adc, ADC1>) -> Self {
        let mut temp_channel = adc.enable_temperature();
        Self { adc, temp_channel }
    }

    fn gen_seed(&mut self) -> u64 {
        let now = Instant::now().as_ticks();
        let temp = self.adc.read_internal(&mut self.temp_channel) as u64;
        now ^ (temp << 48)
    }
}
