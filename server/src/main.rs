#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

mod database;

use aucpace::{AuCPaceServer, ClientMessage};
use core::fmt::Write as _;
use database::SingleUserDatabase;
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::time::Hertz;
use embassy_stm32::usart::{Config, Uart, UartRx};
use embassy_stm32::{interrupt, peripherals};
use embassy_time::{Duration, Instant};
use heapless::String;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use {defmt_rtt as _, panic_probe as _};

#[cfg(not(feature = "strong"))]
use aucpace::Database;

#[cfg(feature = "strong")]
use aucpace::StrongDatabase;

#[cfg(feature = "partial")]
use aucpace::PartialAugDatabase;

const K1: usize = 16;
const RECV_BUF_LEN: usize = 1024;

#[cfg(feature = "static_ssid")]
const SSID: [u8; 32] = [
    60, 173, 56, 252, 74, 141, 171, 146, 102, 169, 149, 169, 158, 106, 87, 232, 220, 141, 251, 73,
    39, 130, 105, 184, 93, 87, 195, 23, 246, 158, 85, 226,
];

/// Writing to a heapless::String then sending and clearing is annoying
macro_rules! fmt_log {
    (ERROR, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::error!("{}", $s.as_str());
        $s.clear();
    };
    (WARN, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::warn!("{}", $s.as_str());
        $s.clear();
    };
    (INFO, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::info!("{}", $s.as_str());
        $s.clear();
    };
    (DEBUG, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::debug!("{}", $s.as_str());
        $s.clear();
    };
    (TRACE, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::trace!("{}", $s.as_str());
        $s.clear();
    };
}

/// function like macro to wrap sending data over USART2, returns the number of bytes sent
macro_rules! send {
    ($tx:ident, $buf:ident, $msg:ident) => {{
        let serialised = postcard::to_slice_cobs(&$msg, &mut $buf).unwrap();
        unwrap!($tx.write(&serialised).await);
        serialised.len()
    }};
}

/// function like macro to wrap receiving data over USART2
macro_rules! recv {
    ($recvr:ident, $s:ident) => {
        loop {
            let parsed = $recvr.recv_msg().await;
            match parsed {
                Ok(msg) => {
                    fmt_log!(DEBUG, $s, "Parsed message - {msg:?}");
                    break msg;
                }
                Err(e) => {
                    fmt_log!(ERROR, $s, "Failed to parse message - {e:?}");
                }
            };
        }
    };
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    let mut rcc_config: embassy_stm32::rcc::Config = Default::default();
    rcc_config.sys_ck = Some(Hertz::mhz(84));
    let mut board_config: embassy_stm32::Config = Default::default();
    board_config.rcc = rcc_config;
    let p = embassy_stm32::init(board_config);
    info!("Initialised peripherals.");

    // configure USART2 which goes over the USB port on this board
    let mut config = Config::default();
    config.baudrate = 28800;
    let irq = interrupt::take!(USART2);
    let (mut tx, rx) =
        Uart::new(p.USART2, p.PA3, p.PA2, irq, p.DMA1_CH6, p.DMA1_CH5, config).split();
    info!("Configured USART2.");

    // configure the RNG, kind of insecure but this is just a demo and I don't have real entropy
    let now = Instant::now().as_micros();
    let server_rng = ChaCha8Rng::seed_from_u64(now);
    info!("Seeded RNG - seed = {}", now);

    // create our AuCPace server
    let mut base_server: AuCPaceServer<sha2::Sha512, _, K1> = AuCPaceServer::new(server_rng);
    let mut database: SingleUserDatabase<100> = SingleUserDatabase::default();
    info!("Created the AuCPace Server and the Single User Database");

    // create something to receive messages
    let mut buf = [0u8; 1024];
    let mut receiver = MsgReceiver::new(rx);
    let mut s: String<1024> = String::new();
    info!("Receiver and buffers set up");

    // wait for a user to register themselves
    info!("Waiting for a registration packet.");
    #[cfg_attr(not(feature = "partial"), allow(unused))]
    let user = loop {
        let msg = recv!(receiver, s);
        #[cfg(not(feature = "strong"))]
        if let ClientMessage::Registration {
            username,
            salt,
            params,
            verifier,
        } = msg
        {
            if username.len() > 100 {
                error!("Attempted to register with a username thats too long.");
            } else {
                database.store_verifier(username, salt, None, verifier, params);
                info!("Registered {:a} for AuCPace", username);
                break username;
            }
        }

        #[cfg(feature = "strong")]
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

    #[cfg(feature = "partial")]
    {
        let (priv_key, pub_key) = base_server.generate_long_term_keypair();
        // it is fine to unwrap here because we have already registered
        // a verifier for the user with store_verifier
        database
            .store_long_term_keypair(user, priv_key, pub_key)
            .unwrap();
        info!("Stored a long term keypair for {:a}", user);
    }

    loop {
        let mut time_taken = Duration::default();

        let start = Instant::now();
        let mut session_rng = ChaCha8Rng::seed_from_u64(start.as_micros());
        let mut bytes_sent = 0;
        time_taken += Instant::now().duration_since(start);
        info!("Seeded Session RNG - seed = {}", start.as_micros());

        // now do a key-exchange
        info!("Beginning AuCPace protocol");

        // ===== SSID Establishment =====
        #[cfg(feature = "static_ssid")]
        let server = {
            let t0 = Instant::now();
            let server = base_server.begin_prestablished_ssid(SSID).unwrap();
            time_taken += Instant::now().duration_since(t0);
            info!("Began from static SSID={:02X}", SSID);
            server
        };

        #[cfg(not(feature = "static_ssid"))]
        let server = {
            let t0 = Instant::now();
            let (server, message) = base_server.begin();
            time_taken += Instant::now().duration_since(t0);

            let client_message: ClientMessage<K1> = recv!(receiver, s);
            let t0 = Instant::now();
            let server = if let ClientMessage::Nonce(client_nonce) = client_message {
                server.agree_ssid(client_nonce)
            } else {
                fmt_log!(
                    ERROR,
                    s,
                    "Received invalid client message {:?} - restarting negotiation",
                    client_message
                );
                continue;
            };
            time_taken += Instant::now().duration_since(t0);
            info!("Received Client Nonce");

            // now that we have received the client nonce, send our nonce back
            bytes_sent += send!(tx, buf, message);
            info!("Sent Nonce");

            server
        };

        // ===== Augmentation Layer =====
        let mut client_message = recv!(receiver, s);
        let t0 = Instant::now();
        #[cfg(not(feature = "strong"))]
        let (server, message) = if let ClientMessage::Username(username) = client_message {
            #[cfg(not(feature = "partial"))]
            let ret = server.generate_client_info(username, &database, &mut session_rng);
            #[cfg(feature = "partial")]
            let ret =
                server.generate_client_info_partial_aug(username, &database, &mut session_rng);
            ret
        } else {
            fmt_log!(
                ERROR,
                s,
                "Received invalid client message {:?} - restarting negotiation",
                client_message
            );
            continue;
        };

        #[cfg(feature = "strong")]
        let (server, message) = if let ClientMessage::StrongUsername { username, blinded } =
            client_message
        {
            #[cfg(not(feature = "partial"))]
            let ret =
                server.generate_client_info_strong(username, blinded, &database, &mut session_rng);
            #[cfg(feature = "partial")]
            let ret = server.generate_client_info_partial_strong(
                username,
                blinded,
                &database,
                &mut session_rng,
            );
            match ret {
                Ok(inner) => inner,
                Err(e) => {
                    fmt_log!(
                        ERROR,
                        s,
                        "Receiving client Public Key returned an error {:?}",
                        e
                    );
                    continue;
                }
            }
        } else {
            fmt_log!(
                ERROR,
                s,
                "Received invalid client message {:?} - restarting negotiation",
                client_message
            );
            continue;
        };
        time_taken += Instant::now().duration_since(t0);

        bytes_sent += send!(tx, buf, message);
        #[cfg(not(feature = "strong"))]
        {
            info!("Received Client Username");
            info!("Sent AugmentationInfo");
        }
        #[cfg(feature = "strong")]
        {
            info!("Received Client Username and Blinded Point");
            info!("Sent Strong Augmentation Info");
        }

        // ===== CPace substep =====
        let t0 = Instant::now();
        let ci = "Server-USART2-Client-SerialPort";
        let (server, message) = server.generate_public_key(ci);
        time_taken += Instant::now().duration_since(t0);
        bytes_sent += send!(tx, buf, message);
        info!("Sent PublicKey");

        client_message = recv!(receiver, s);
        let ClientMessage::PublicKey(client_pubkey) = client_message else {
            fmt_log!(
                    ERROR,
                    s,
                    "Received invalid client message {:?}",
                    client_message
                );
            continue;
        };

        let key = if cfg!(feature = "implicit") {
            match server.implicit_auth(client_pubkey) {
                Ok(s) => s,
                Err(e) => {
                    fmt_log!(
                        ERROR,
                        s,
                        "Receiving client Public Key returned an error {:?}",
                        e
                    );
                    continue;
                }
            }
        } else {
            let t0 = Instant::now();
            let server = match server.receive_client_pubkey(client_pubkey) {
                Ok(s) => s,
                Err(e) => {
                    fmt_log!(
                        ERROR,
                        s,
                        "Receiving client Public Key returned an error {:?}",
                        e
                    );
                    continue;
                }
            };
            time_taken += Instant::now().duration_since(t0);
            info!("Received Client PublicKey");

            // ===== Explicit Mutual Authentication =====
            client_message = recv!(receiver, s);
            let t0 = Instant::now();
            let (key, message) = if let ClientMessage::Authenticator(ca) = client_message {
                match server.receive_client_authenticator(ca) {
                    Ok(inner) => inner,
                    Err(e) => {
                        fmt_log!(
                            ERROR,
                            s,
                            "Client failed the Explicit Mutual Authentication check - {e:?}"
                        );
                        continue;
                    }
                }
            } else {
                fmt_log!(
                    ERROR,
                    s,
                    "Received invalid client message {:?}",
                    client_message
                );
                continue;
            };

            time_taken += Instant::now().duration_since(t0);
            bytes_sent += send!(tx, buf, message);

            info!("Sent Authenticator");

            key
        };

        info!("Derived final key: {:02X}", key.as_slice());
        info!("Total bytes sent: {}", bytes_sent);
        info!("Total computation time: {}ms - {} ticks", time_taken.as_millis(), time_taken.as_ticks());
    }
}

struct MsgReceiver<'uart> {
    buf: [u8; RECV_BUF_LEN],
    idx: usize,
    rx: UartRx<'uart, peripherals::USART2, peripherals::DMA1_CH5>,
    reset_pos: Option<usize>,
}

impl<'uart> MsgReceiver<'uart> {
    fn new(rx: UartRx<'uart, peripherals::USART2, peripherals::DMA1_CH5>) -> Self {
        Self {
            buf: [0u8; 1024],
            idx: 0,
            rx,
            reset_pos: None,
        }
    }

    async fn recv_msg(&mut self) -> postcard::Result<ClientMessage<'_, K1>> {
        // reset the state
        // copy all the data we read after the 0 byte to the start of the self.buffer
        if let Some(zi) = self.reset_pos {
            self.buf.copy_within(zi + 1..self.idx, 0);
            self.idx = self.idx.saturating_sub(zi + 1);
            self.reset_pos = None;
        }

        // if there is a zero in the message buffer try to process that msg
        let previous_msg_zi = self.buf[..self.idx].iter().position(|x| *x == 0);

        let zi = loop {
            if let Some(zi) = previous_msg_zi {
                break zi;
            }

            // read as much as we can off the wire
            let count = unwrap!(self.rx.read_until_idle(&mut self.buf[self.idx..]).await);
            let zero_idx = if count == 0 {
                continue;
            } else {
                // log that we managed to read some data
                trace!(
                    "Read {} bytes - {:02X}",
                    count,
                    self.buf[self.idx..self.idx + count],
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

            break zi;
        };

        trace!("self.buf[..self.idx] = {:02X}", self.buf[..self.idx]);
        trace!(
            "Found zero byte at index {} - {} - {}",
            zi,
            self.buf[zi],
            self.idx
        );

        // store zi for next time
        self.reset_pos = Some(zi);

        // parse the result
        postcard::from_bytes_cobs::<ClientMessage<K1>>(&mut self.buf[..=zi])
    }
}
