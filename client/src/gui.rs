use crate::auth::register_user;
use crate::metadata::Metadata;
use crate::secret_key::SecretKey;
use crate::utils::{compute_vault_key, decrypt_block};
use crate::{auth::establish_key, msg_receiver::MsgReceiver, Client, K1, USART_BAUD};
use aucpace::AuCPaceClient;
use chacha20poly1305::Key;
use eframe::egui;
use egui::{Align, Layout, Pos2, Rect, Ui, Vec2, Visuals};
use egui_extras::{Column, Table, TableBuilder};
use egui_notify::Toasts;
use rand_core::OsRng;
use serialport::{SerialPort, SerialPortType};
use shared::{Action, ActionToken, EncryptedMessage, Message, Response};
use std::io::Write;
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub struct Gui {
    state: State,
    user: String,
    pass: String,
    board_port: String,
    board: Option<MsgReceiver>,
    aucpace_client: Client,
    key: Option<Key>,
    vault_key: Option<Key>,
    metadata: Metadata,
    notifications: Toasts,
}

impl Default for Gui {
    fn default() -> Self {
        let board = serialport::new("/dev/ttyACM0", USART_BAUD)
            .open()
            .ok()
            .map(|mut serial| {
                serial.set_timeout(Duration::from_secs(5)).unwrap();
                MsgReceiver::new(serial)
            });

        Self {
            state: State::default(),
            user: String::default(),
            pass: String::default(),
            board_port: String::from("/dev/ttyACM0"),
            board,
            aucpace_client: AuCPaceClient::new(OsRng),
            key: None,
            vault_key: None,
            metadata: Metadata::default(),
            notifications: Toasts::new(),
        }
    }
}

#[derive(Default)]
enum State {
    #[default]
    Login,
    Homepage,
}

impl eframe::App for Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.notifications.show(ctx);
        egui::TopBottomPanel::top("app_top_bar").show(ctx, |ui| {
            self.board_dropdown(ui);
        });
        egui::CentralPanel::default().show(ctx, |ui| match &mut self.state {
            State::Login => self.login_screen(ui),
            // TODO: add a logout button
            State::Homepage => {
                if !self.metadata.is_populated() {
                    if self
                        .send_action_request(Action::ReadSectorMetadata)
                        .is_none()
                    {
                        self.notifications.warning("Failed to read sector metadata");
                    }

                    if let Some(Response::SectorMetadata { populated }) =
                        self.read_action_response()
                    {
                        self.metadata = Metadata::new(populated);
                    } else {
                        self.notifications
                            .warning("Got invalid response to request.");
                    }
                }

                while let Some(entry_idx) = self.metadata.next_needed_entry_id() {
                    if self
                        .send_action_request(Action::ReadEntryMetadata { entry_idx })
                        .is_none()
                    {
                        self.notifications.warning("Failed to read entry metadata");
                    }

                    if let Some(metadata) = self.read_entry_metadata() {
                        self.metadata.add_entry(entry_idx, metadata)
                    } else {
                        self.notifications
                            .warning("Got invalid response to request.");
                    }
                }
                ui.heading("we at home 😌");
            }
        });
    }
}

impl Gui {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(Visuals::dark());
        Self::default()
    }

    fn board_dropdown(&mut self, ui: &mut Ui) {
        let Ok(ports) = serialport::available_ports() else {
            ui.label("Failed to get availble ports.");
            return;
        };

        egui::ComboBox::from_id_source("board_port_combobox")
            .selected_text(&self.board_port)
            .show_ui(ui, |ui| {
                for port in ports {
                    if matches!(port.port_type, SerialPortType::UsbPort(_)) {
                        let value = ui.selectable_value(
                            &mut self.board_port,
                            port.port_name.clone(),
                            &port.port_name,
                        );

                        if value.changed() {
                            info!("Set board port to {:?}", port.port_name);
                            self.board_port = port.port_name;
                            self.change_board();
                        }
                    }
                }
            });
    }

    fn change_board(&mut self) {
        let board = serialport::new(self.board_port.as_str(), USART_BAUD)
            .open()
            .map(|mut serial| {
                serial.set_timeout(Duration::from_secs(5)).unwrap();
                MsgReceiver::new(serial)
            });

        match board {
            Ok(b) => self.board = Some(b),
            Err(e) => warn!("Failed to open serial port: {e:?}"),
        }
    }

    fn login_screen(&mut self, ui: &mut Ui) {
        const SCALE_FACTOR: f32 = 4.0;
        const WIDTH: f32 = 320.0;
        let w = ui.available_width();
        let h = ui.available_height();
        let rect = Rect::from_center_size(
            Pos2::new(w / 2.0, h / 2.0),
            Vec2::new(WIDTH, h / SCALE_FACTOR),
        );
        ui.allocate_ui_at_rect(rect, |ui| {
            ui.vertical_centered(|ui| ui.heading("Demo Vault"));
            ui.add_space(10.0);
            ui.vertical_centered_justified(|ui| {
                let user_input = egui::TextEdit::singleline(&mut self.user)
                    .hint_text("Username")
                    .margin(Vec2::new(10.0, 10.0));
                ui.add(user_input);
                ui.add_space(5.0);
                let pass_input = egui::TextEdit::singleline(&mut self.pass)
                    .hint_text("Password")
                    .password(true)
                    .margin(Vec2::new(10.0, 10.0));
                ui.add(pass_input);
                ui.add_space(10.0);
                TableBuilder::new(ui)
                    .columns(Column::exact(WIDTH / 2.0 - 4.0), 2)
                    .body(|mut table_ui| {
                        table_ui.row(20.0, |mut row| {
                            row.col(|ui| {
                                if ui.button("Login").clicked() {
                                    self.login(ui.ctx());
                                }
                            });
                            row.col(|ui| {
                                if ui.button("Register").clicked() {
                                    self.register(ui.ctx());
                                }
                            });
                        });
                    });
            });
        });
    }

    fn login(&mut self, ctx: &egui::Context) {
        debug!("Attempting to login as {}", self.user);
        let Some(receiver) = &mut self.board else {
            self.notifications.warning("No serial connection, cannot login.");
            return;
        };

        // setup the channel to receive the key
        let res = establish_key(
            receiver,
            &mut self.aucpace_client,
            self.user.as_bytes(),
            self.pass.as_bytes(),
        );
        match res {
            Ok(key) => {
                self.notifications.info("Login successful.");
                self.key = Some(key)
            }
            Err(e) => {
                error!("Failed to establish shared key: {e:?}");
                self.notifications
                    .error(format!("Failed to establish shared key: {e:?}"));
                return;
            }
        }
        self.state = State::Homepage;
        ctx.request_repaint();

        let Ok(sk) = std::fs::read_to_string("demo.vault") else {
            self.notifications.error("Failed to read demo.vault, unable to decrypt any entries")
                .set_duration(None);
            return;
        };

        let Ok(sk) = sk.parse() else {
            self.notifications.error("Failed to parse secret key from demo.vault, unable to decrypt any entries")
                .set_duration(None);
            return;
        };

        let Ok(vk) = compute_vault_key(self.pass.as_bytes(), sk) else {
            self.notifications.error("Failed to vault key from secret key, unable to decrypt any entries")
                .set_duration(None);
            return;
        };

        self.vault_key = Some(vk);
    }

    fn register(&mut self, ctx: &egui::Context) {
        debug!("Attempting to register as {}", self.user);
        let Some(receiver) = &mut self.board else {
            self.notifications.warning("No serial connection, cannot Register.");
            return;
        };

        register_user(
            receiver,
            &mut self.aucpace_client,
            self.user.as_bytes(),
            self.pass.as_bytes(),
        )
        .ok();

        // generate a secret key
        let mut sk = SecretKey::generate(&mut OsRng);
        if let Err(_) = std::fs::write("demo.vault", format!("{sk}")) {
            self.notifications
                .error(
                    "Failed to write demo.vault, will be unable to add new entries to the vault.",
                )
                .set_duration(None);
        }
        self.login(ctx);
    }

    fn read_action_token(&mut self) -> Option<ActionToken> {
        let msg = self.read_message()?;
        let Message::Token(action_token) = msg else {
            return None;
        };

        Some(action_token)
    }

    fn send_action_request(&mut self, action: Action) -> Option<()> {
        let token = self.read_action_token()?;
        let msg = Message::ActionRequest { action, token };
        let mut ser_msg = postcard::to_stdvec(&msg).ok()?;

        let key = &self.key?;
        let enc_msg = EncryptedMessage::encrypt(&mut ser_msg, key, &mut OsRng).ok()?;
        let ser_enc_msg = postcard::to_stdvec_cobs(&enc_msg).ok()?;

        let msg_receiver = self.board.as_mut()?;
        msg_receiver.serial_mut().write_all(&ser_enc_msg).ok()
    }

    fn read_action_response(&mut self) -> Option<Response> {
        let msg = self.read_message()?;
        let Message::ActionResponse { response } = msg else {
            return None;
        };

        Some(response)
    }

    fn read_message(&mut self) -> Option<Message> {
        let msg_receiver = self.board.as_mut()?;
        let key = &self.key?;

        let enc_msg: EncryptedMessage = msg_receiver.recv_msg().ok()?;
        let mut buf = [0u8; 512];

        let msg = enc_msg.decrypt_into(key, &mut buf).ok()?;
        postcard::from_bytes(msg).ok()
    }

    fn read_entry_metadata(&mut self) -> Option<String> {
        let msg = self.read_message()?;
        let Message::ActionResponse { response } = msg else {
            return None;
        };
        let Response::EntryMetadata { metadata } = response else {
            return None;
        };

        let dec = decrypt_block(metadata, &self.key?).ok()?;
        if let Some(zi) = dec.iter().position(|x| *x == 0) {
            Some(String::from_utf8_lossy(&dec[..zi]).ok())
        } else {
            Some(String::from_utf8_lossy(&dec).ok())
        }
    }
}
