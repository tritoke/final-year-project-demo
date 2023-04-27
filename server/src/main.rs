#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

mod auth;
mod database;
mod msg_receiver;
mod seed_gen;
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
    let mut base_server: AuCPaceServer<Sha512, _, K1> = AuCPaceServer::new(server_rng);
    let mut database = unwrap!(storage.retrieve_database());
    debug!("Created the Strong AuCPace Server and the retrieved the Single User Database");

    // create something to receive messages
    let mut buf = [0u8; 1024];
    let mut receiver = MsgReceiver::new(rx);
    debug!("Receiver and buffers set up");

    // if the database is empty then register a new user
    if !database.is_populated() {
        register_user(&mut database, &mut receiver, &mut tx, &mut buf).await;
        let mut csprng = ChaCha8Rng::seed_from_u64(seed_generator.gen_seed());
        unwrap!(storage.store_database(&database, &mut csprng));
    }

    let key = establish_key(
        &mut base_server,
        &database,
        &mut seed_generator,
        &mut receiver,
        &mut tx,
        &mut buf,
    )
    .await;
    debug!("Established strong shared key");

    loop {}
}
