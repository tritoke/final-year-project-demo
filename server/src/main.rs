#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

pub mod auth;
pub mod database;
pub mod msg_receiver;
pub mod seed_gen;
pub mod storage;

use aucpace::AuCPaceServer;
use auth::{establish_key, register_user};
use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, Key, KeyInit};
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::interrupt;
use embassy_stm32::time::Hertz;
use embassy_stm32::usart::{Config, Uart, UartTx};
use rand_chacha::ChaCha8Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use {defmt_rtt as _, panic_probe as _};

use crate::msg_receiver::MsgReceiver;
use crate::seed_gen::SeedGenerator;
use crate::storage::{Entry, Storage};
use embassy_stm32::flash::Flash;
use embassy_stm32::peripherals::{DMA1_CH6, USART2};
use embassy_time::Delay;
use embedded_hal::prelude::_embedded_hal_blocking_delay_DelayMs;
use sha3::Sha3_512;
use shared::{ActionToken, EncryptedMessage, Message};

// AuCPace nonce-size constant
const K1: usize = 16;

// configure the exponential back off for password retries
const BASE_SLEEP_MS: u32 = 10;

// generated new each time the server is compiled
const DB_ENC_KEY: [u8; 32] = const_random::const_random!([u8; 32]);

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

    // configure the seed generator
    let mut seed_generator = SeedGenerator::new(p.ADC1);
    debug!("Configured Seed generator.");

    // setup the flash storage manager
    let mut storage = unwrap!(Storage::new(Flash::new(p.FLASH)));
    debug!("Set up storage: metadata = {}", storage.metadata);

    // create the seed generator then seed a CSPRNG from it
    let seed = seed_generator.gen_seed();
    let server_rng = ChaCha8Rng::seed_from_u64(seed);
    debug!("Seeded RNG - seed = {}", seed);

    // create our AuCPace server
    let mut base_server: AuCPaceServer<Sha3_512, _, K1> = AuCPaceServer::new(server_rng);
    let mut database = unwrap!(storage.retrieve_database());
    debug!("Created the Strong AuCPace Server and the retrieved the Single User Database");

    // create something to receive messages
    let mut buf = [0u8; 1024];
    let mut receiver = MsgReceiver::new(rx);
    debug!("Receiver and buffers set up");

    // if the database is empty then register a new user
    let mut store_db = false;
    debug!("database.is_populated(): {}", database.is_populated());
    if !database.is_populated() {
        register_user(&mut database, &mut receiver).await;
        store_db = true;
    }

    let mut session_rng = ChaCha8Rng::seed_from_u64(seed_generator.gen_seed());
    let mut sleep_ms = BASE_SLEEP_MS;
    loop {
        info!("Waiting for login");
        let Some(key) = establish_key(
            &mut base_server,
            &database,
            &mut session_rng,
            &mut receiver,
            &mut tx,
            &mut buf,
        )
        .await else {
            info!("Login failed - timed out for {}ms", sleep_ms);
            Delay.delay_ms(sleep_ms);
            sleep_ms = sleep_ms.saturating_mul(BASE_SLEEP_MS);
            continue;
        };
        sleep_ms = BASE_SLEEP_MS;
        debug!("Established strong shared key");

        // if the DB was empty before, store it now
        if store_db {
            let mut csprng = ChaCha8Rng::seed_from_u64(seed_generator.gen_seed());
            unwrap!(storage.store_database(&database, &mut csprng));
            store_db = false;
            debug!("Stored database");
        }

        // exchange messages until we get another AuCPace message
        let mut buf = [0u8; 512];
        loop {
            // send an ActionToken to the
            let token = ActionToken::random(&mut session_rng);
            let message = Message::Token(token);
            if let Err(e) = send_message(&mut tx, message, &key, &mut session_rng).await {
                debug!("Error sending message: {}", e);
            }

            let Ok(enc_message) = receiver.recv_msg::<EncryptedMessage>().await else {
                // if we fail to parse a message retry parsing it as an AuCPace message
                receiver.unparse_last_message();
                break;
            };

            let dec = match enc_message.decrypt_into(&key, &mut buf) {
                Ok(inner) => inner,
                Err(e) => {
                    debug!("Failed to decrypt message - {}", Debug2Format(&e));
                    break;
                }
            };
            let Ok(message) = postcard::from_bytes::<Message>(dec) else {
                debug!("Failed to deserialise message");
                break;
            };
            info!("Received message: {}", Debug2Format(&message));
        }
    }
}

#[derive(Format)]
enum SendMessageError {
    Postcard(postcard::Error),
    ChaCha20(#[defmt(Debug2Format)] chacha20poly1305::Error),
    Usart(embassy_stm32::usart::Error),
}

impl From<postcard::Error> for SendMessageError {
    fn from(value: postcard::Error) -> Self {
        Self::Postcard(value)
    }
}

impl From<chacha20poly1305::Error> for SendMessageError {
    fn from(value: chacha20poly1305::Error) -> Self {
        Self::ChaCha20(value)
    }
}

impl From<embassy_stm32::usart::Error> for SendMessageError {
    fn from(value: embassy_stm32::usart::Error) -> Self {
        Self::Usart(value)
    }
}

async fn send_message(
    tx: &mut UartTx<'_, USART2, DMA1_CH6>,
    message: Message,
    key: &Key,
    csprng: &mut impl CryptoRngCore,
) -> Result<(), SendMessageError> {
    let mut buf = [0u8; 512];

    // first serialise to the buffer
    let serialised = postcard::to_slice(&message, &mut buf)?;

    // new encrypt that with the strong shared key
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(csprng);
    let tag = cipher.encrypt_in_place_detached(&nonce, b"", serialised)?;

    let enc_message = EncryptedMessage {
        enc_data: serialised,
        nonce: nonce
            .as_slice()
            .try_into()
            .expect("length invariant broken"),
        tag: tag.as_slice().try_into().expect("length invariant broken"),
    };

    // now serialise the encrypted message
    let mut buf2_electic_boogaloo = [0u8; 512];
    let serialised = postcard::to_slice_cobs(&enc_message, &mut buf2_electic_boogaloo)?;

    // send it!
    tx.write(serialised).await?;

    Ok(())
}
