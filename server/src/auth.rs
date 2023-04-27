use crate::{MsgReceiver, SeedGenerator, SingleUserDatabase, K1};
use aucpace::{AuCPaceServer, ClientMessage, ServerMessage, StrongDatabase};
use defmt::{debug, error, info, trace, warn};
use embassy_stm32::peripherals::{DMA1_CH6, USART2};
use embassy_stm32::usart::UartTx;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::Sha512;

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
