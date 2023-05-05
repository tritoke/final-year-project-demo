use crate::auth::register_user;
use crate::metadata::Metadata;
use crate::secret_key::SecretKey;
use crate::utils::{compute_vault_key, decrypt_block, encrypt_block};
use crate::{auth::establish_key, msg_receiver::MsgReceiver, Client, USART_BAUD};
use aucpace::AuCPaceClient;
use chacha20poly1305::Key;
use eframe::egui;
use egui::{Align, Layout, Pos2, Rect, RichText, Ui, Vec2, Visuals};
use egui_extras::{Column, TableBuilder};
use egui_notify::Toasts;
use rand_core::OsRng;
use serialport::SerialPortType;
use shared::{Action, ActionToken, EncryptedMessage, Message, Response};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

const SERIAL_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_BACKOFF_TIME: Duration = Duration::from_millis(10);

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
    show_new_entry_window: bool,
    new_entry_title: String,
    new_entry_username: String,
    new_entry_password: String,
    exp_backoff_metadata_fetch_fail_time: Duration,
    metadata_last_fetch_attempt_time: Instant,
    currently_shown_entry_idx: Option<u32>,
    current_entry_user: String,
    current_entry_pass: String,
    current_entry_title: String,
    current_entry_show_pass: bool,
    show_change_entry_window: bool,
    change_entry_user: String,
    change_entry_pass: String,
    change_entry_title: String,
    change_entry_idx: Option<u32>,
}

impl Default for Gui {
    fn default() -> Self {
        let board = serialport::new("/dev/ttyACM0", USART_BAUD)
            .open()
            .ok()
            .map(|mut serial| {
                serial.set_timeout(SERIAL_TIMEOUT).unwrap();
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
            show_new_entry_window: false,
            new_entry_title: String::new(),
            new_entry_username: String::new(),
            new_entry_password: String::new(),
            exp_backoff_metadata_fetch_fail_time: DEFAULT_BACKOFF_TIME,
            metadata_last_fetch_attempt_time: Instant::now(),
            currently_shown_entry_idx: None,
            current_entry_user: String::new(),
            current_entry_pass: String::new(),
            current_entry_title: String::new(),
            current_entry_show_pass: false,
            show_change_entry_window: false,
            change_entry_user: String::new(),
            change_entry_pass: String::new(),
            change_entry_title: String::new(),
            change_entry_idx: None,
        }
    }
}

#[derive(Default, PartialEq, Eq, Copy, Clone)]
enum State {
    #[default]
    Login,
    Homepage,
}

impl eframe::App for Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.notifications.show(ctx);
        egui::TopBottomPanel::top("app_top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                self.board_dropdown(ui);

                ui.with_layout(Layout::right_to_left(Align::TOP), |ui| {
                    if self.state == State::Homepage && ui.button("Add Entry").clicked() {
                        self.show_new_entry_window = true;
                    }
                    if self.state != State::Login {
                        if ui.button("Logout").clicked() {
                            self.show_new_entry_window = false;
                            self.state = State::Login;
                            self.user.clear();
                            self.pass.clear();
                            self.new_entry_title.clear();
                            self.new_entry_username.clear();
                            self.new_entry_password.clear();
                        }

                        if ui
                            .button("Delete EVERYTHING")
                            .on_hover_text(
                                "Double click to delete everything - this is unrecoverable.",
                            )
                            .double_clicked()
                        {
                            let Some(()) = self.send_action_request(Action::TheNsaAreHere) else {
                                self.notifications.error("Failed to delete everything");
                                return;
                            };
                            let Some(Response::Success) = self.read_action_response() else {
                                self.notifications.error("Failed to delete everything");
                                return;
                            };
                            *self = Self::default();
                        }
                    }
                });
            });
        });

        if self.show_new_entry_window {
            let mut open = true;
            egui::Window::new("New Entry")
                .open(&mut open)
                .show(ctx, |ui| {
                    self.new_entry_window(ui);
                });
            self.show_new_entry_window = open;
        }

        if self.show_change_entry_window {
            let mut open = true;
            egui::Window::new("Change Entry")
                .open(&mut open)
                .show(ctx, |ui| {
                    self.change_entry_window(ui);
                });
            self.show_change_entry_window = open;
        }

        match self.state {
            State::Login => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.login_screen(ui);
                });
            }
            State::Homepage => {
                // load metadata -- this is basically a nop once loaded
                self.load_metadata();
                self.entry_sidebar(ctx);
                self.main_entry(ctx);
            }
        }
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

    fn load_metadata(&mut self) {
        if Instant::now().duration_since(self.metadata_last_fetch_attempt_time)
            < self.exp_backoff_metadata_fetch_fail_time
        {
            return;
        }

        if !self.metadata.is_populated() {
            if self
                .send_action_request(Action::ReadSectorMetadata)
                .is_none()
            {
                self.notifications.warning("Failed to read sector metadata");
            }

            if let Some(Response::SectorMetadata { populated }) = self.read_action_response() {
                self.metadata = Metadata::new(populated);
            } else {
                self.notifications
                    .warning("Got invalid response to request.");
            }
        }

        if let Some(entry_idx) = self.metadata.next_needed_entry_id() {
            debug!("entry_idx = {entry_idx}");
            if self
                .send_action_request(Action::ReadEntryMetadata { entry_idx })
                .is_none()
            {
                self.notifications.warning("Failed to read entry metadata");
            }

            if let Some(metadata) = self.read_entry_metadata() {
                debug!("Loaded entry_idx = {entry_idx}, metadata = {metadata:?}");
                self.metadata.add_entry(entry_idx, metadata);
                self.exp_backoff_metadata_fetch_fail_time = DEFAULT_BACKOFF_TIME;
            } else {
                debug!("Failed to read entry metadata");
                self.metadata_last_fetch_attempt_time = Instant::now();
                self.exp_backoff_metadata_fetch_fail_time *= 2;

                self.notifications
                    .warning("Got invalid response to request.");
            }
        }
    }

    fn left_right_row(
        ui: &mut Ui,
        add_left_contents: impl FnOnce(&mut Ui),
        add_right_contents: impl FnOnce(&mut Ui),
    ) {
        ui.horizontal(|ui| {
            add_left_contents(ui);
            ui.with_layout(Layout::right_to_left(Align::Center), add_right_contents);
        });
    }

    fn new_entry_window(&mut self, ui: &mut Ui) {
        const TEXT_EDIT_WIDTH: f32 = 200.0;
        Self::left_right_row(
            ui,
            |ui| {
                ui.heading("Entry Name:");
            },
            |ui| {
                egui::TextEdit::singleline(&mut self.new_entry_title)
                    .desired_width(TEXT_EDIT_WIDTH)
                    .show(ui);
            },
        );
        ui.separator();
        Self::left_right_row(
            ui,
            |ui| {
                ui.heading("Username:");
            },
            |ui| {
                egui::TextEdit::singleline(&mut self.new_entry_username)
                    .desired_width(TEXT_EDIT_WIDTH)
                    .show(ui);
            },
        );
        Self::left_right_row(
            ui,
            |ui| {
                ui.heading("Password:");
            },
            |ui| {
                egui::TextEdit::singleline(&mut self.new_entry_password)
                    .desired_width(TEXT_EDIT_WIDTH)
                    .show(ui);
            },
        );
        ui.add_space(10.0);
        ui.vertical_centered(|ui| {
            if ui.button("Add entry").clicked() {
                let title = self.new_entry_title.as_bytes();
                let user = self.new_entry_username.as_bytes();
                let pass = self.new_entry_password.as_bytes();

                // first validate the size requirements
                if title.len() > 100 {
                    self.notifications.warning(format!(
                        "Entry title is {} characters too long",
                        title.len() - 100
                    ));
                    return;
                } else if title.is_empty() {
                    self.notifications.warning("Entry title cannot be empty.");
                    return;
                }

                if user.len() > 60 {
                    self.notifications.warning(format!(
                        "Entry username is {} characters too long",
                        user.len() - 60
                    ));
                    return;
                } else if user.is_empty() {
                    self.notifications
                        .warning("Entry username cannot be empty.");
                    return;
                }

                if pass.len() > 40 {
                    self.notifications.warning(format!(
                        "Entry password is {} characters too long",
                        pass.len() - 40
                    ));
                    return;
                } else if pass.is_empty() {
                    self.notifications
                        .warning("Entry password cannot be empty.");
                    return;
                }

                let Some(key) = self.vault_key.as_ref() else {
                    self.notifications.error("No vault key - cannot create entry.");
                    return;
                };

                self.notifications.info("Creating a new entry.");

                // create the encrypted entry
                // 100 chars for metadata
                let mut meta_buf = [0u8; 100];
                meta_buf[..title.len()].copy_from_slice(title);
                let Ok(meta_ct ) = encrypt_block(meta_buf, key) else {
                    self.notifications.error("Failed to encrypt data.");
                    return;
                };

                // first 60 chars are for username
                // last 40 chars are for username
                let mut data_buf = [0u8; 100];
                let (user_buf, pass_buf) = data_buf.split_at_mut(60);
                user_buf[..user.len()].copy_from_slice(user);
                pass_buf[..pass.len()].copy_from_slice(pass);
                let Ok(data_ct) = encrypt_block(data_buf, key) else {
                    self.notifications.error("Failed to encrypt data.");
                    return;
                };

                // now we can construct the message
                let action = Action::Create {
                    enc_data: data_ct
                        .as_slice()
                        .try_into()
                        .expect("length invariant broken."),
                    metadata: meta_ct
                        .as_slice()
                        .try_into()
                        .expect("length invariant broken."),
                };

                self.send_action_request(action);

                let Some(resp) = self.read_action_response() else {
                    self.notifications.warning("Failed to read response, entry creation may have failed");
                    return;
                };

                let Response::NewEntry { index } = resp else {
                    self.notifications.error("Got invalid response, please try again.");
                    return;
                };

                // add the new entry to the metadata
                self.metadata.add_entry(index, std::mem::take(&mut self.new_entry_title));
                self.new_entry_password.clear();
                self.new_entry_username.clear();
                self.show_new_entry_window = false;
                self.notifications.info("Successfully created new entry.");
            }
        });
    }

    fn entry_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("Entry sidebar")
            .exact_width(300.0)
            .show(ctx, |ui| {
                ui.vertical_centered_justified(|ui| {
                    let mut set_entry = None;
                    for (entry_idx, entry_name) in self.metadata.entries() {
                        let label_text = entry_name
                            .clone()
                            .unwrap_or_else(|| String::from("-- NOT YET LOADED --"));
                        let label = ui.selectable_label(
                            self.currently_shown_entry_idx == Some(*entry_idx),
                            label_text,
                        );
                        if label.clicked() {
                            set_entry = Some(*entry_idx);
                        }
                    }
                    if let Some(entry_idx) = set_entry {
                        self.set_current_entry(Some(entry_idx));
                    }
                });
            });
    }

    fn change_entry_window(&mut self, ui: &mut Ui) {
        const TEXT_EDIT_WIDTH: f32 = 200.0;
        Self::left_right_row(
            ui,
            |ui| {
                ui.heading("Entry Name:");
            },
            |ui| {
                egui::TextEdit::singleline(&mut self.change_entry_title)
                    .desired_width(TEXT_EDIT_WIDTH)
                    .show(ui);
            },
        );
        ui.separator();
        Self::left_right_row(
            ui,
            |ui| {
                ui.heading("Username:");
            },
            |ui| {
                egui::TextEdit::singleline(&mut self.change_entry_user)
                    .desired_width(TEXT_EDIT_WIDTH)
                    .show(ui);
            },
        );
        Self::left_right_row(
            ui,
            |ui| {
                ui.heading("Password:");
            },
            |ui| {
                egui::TextEdit::singleline(&mut self.change_entry_pass)
                    .desired_width(TEXT_EDIT_WIDTH)
                    .show(ui);
            },
        );
        ui.add_space(10.0);
        ui.vertical_centered(|ui| {
            if ui.button("Update Entry").clicked() {
                let title = self.change_entry_title.as_bytes();
                let user = self.change_entry_user.as_bytes();
                let pass = self.change_entry_pass.as_bytes();

                // first validate the size requirements
                if title.len() > 100 {
                    self.notifications.warning(format!(
                        "Entry title is {} characters too long",
                        title.len() - 100
                    ));
                    return;
                } else if title.is_empty() {
                    self.notifications.warning("Entry title cannot be empty.");
                    return;
                }

                if user.len() > 60 {
                    self.notifications.warning(format!(
                        "Entry username is {} characters too long",
                        user.len() - 60
                    ));
                    return;
                } else if user.is_empty() {
                    self.notifications
                        .warning("Entry username cannot be empty.");
                    return;
                }

                if pass.len() > 40 {
                    self.notifications.warning(format!(
                        "Entry password is {} characters too long",
                        pass.len() - 40
                    ));
                    return;
                } else if pass.is_empty() {
                    self.notifications
                        .warning("Entry password cannot be empty.");
                    return;
                }

                let Some(key) = self.vault_key.as_ref() else {
                    self.notifications.error("No vault key - cannot change entry.");
                    return;
                };

                self.notifications.info("Changing entry.");

                // create the encrypted entry
                // 100 chars for metadata
                let mut meta_buf = [0u8; 100];
                meta_buf[..title.len()].copy_from_slice(title);
                let Ok(meta_ct ) = encrypt_block(meta_buf, key) else {
                    self.notifications.error("Failed to encrypt data.");
                    return;
                };

                // first 60 chars are for username
                // last 40 chars are for username
                let mut data_buf = [0u8; 100];
                let (user_buf, pass_buf) = data_buf.split_at_mut(60);
                user_buf[..user.len()].copy_from_slice(user);
                pass_buf[..pass.len()].copy_from_slice(pass);
                let Ok(data_ct) = encrypt_block(data_buf, key) else {
                    self.notifications.error("Failed to encrypt data.");
                    return;
                };

                // now we can construct the message
                let action = Action::Update {
                    entry_idx: self.change_entry_idx.unwrap(),
                    new_enc_data: data_ct
                        .as_slice()
                        .try_into()
                        .expect("length invariant broken."),
                    new_metadata: meta_ct
                        .as_slice()
                        .try_into()
                        .expect("length invariant broken."),
                };

                self.send_action_request(action);

                let Some(resp) = self.read_action_response() else {
                    self.notifications.warning("Failed to read response, entry change may have failed");
                    return;
                };

                let Response::NewEntry { index } = resp else {
                    self.notifications.error("Got invalid response, please try again.");
                    return;
                };

                // add the new entry to the metadata
                if self.currently_shown_entry_idx == self.change_entry_idx {
                    self.set_current_entry(Some(index));
                }
                self.metadata.del_entry(self.change_entry_idx.unwrap());
                self.metadata.add_entry(index, std::mem::take(&mut self.change_entry_title));
                self.change_entry_idx = None;
                self.change_entry_pass.clear();
                self.change_entry_user.clear();
                self.show_change_entry_window = false;
                self.notifications.info("Successfully changed entry.");
            }
        });
    }

    fn set_current_entry(&mut self, entry_idx: Option<u32>) {
        self.currently_shown_entry_idx = entry_idx;
        self.current_entry_pass.clear();
        self.current_entry_user.clear();
        self.current_entry_title.clear();
        self.current_entry_show_pass = false;
    }

    fn main_entry(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // show nothing if we don't have an entry
            let Some(entry_idx) = self.currently_shown_entry_idx else {
                return;
            };
            if self.current_entry_user.is_empty() {
                if self
                    .send_action_request(Action::Read { entry_idx })
                    .is_none()
                {
                    self.notifications.error("Failed to get the entry");
                    return;
                };
                let Some(Response::Entry { data, metadata }) = self.read_action_response() else {
                    self.notifications.error("Failed to read response.");
                    return;
                };
                let Some(key) = self.vault_key.as_ref() else {
                    self.notifications.error("No vault key present, cannot decrypt entry.");
                    return;
                };
                let Ok(dec_data) = decrypt_block(data, key) else {
                    self.notifications.error("Failed to decrypt data.");
                    return;
                };
                let Ok(dec_metadata) = decrypt_block(metadata, key) else {
                    self.notifications.error("Failed to decrypt metadata.");
                    return;
                };
                let (user_ref, pass_ref) = dec_data.split_at(60);
                let user_len = user_ref
                    .iter()
                    .position(|x| *x == 0)
                    .unwrap_or(user_ref.len());
                self.current_entry_user =
                    String::from_utf8_lossy(&user_ref[..user_len]).to_string();

                let pass_len = pass_ref
                    .iter()
                    .position(|x| *x == 0)
                    .unwrap_or(pass_ref.len());
                self.current_entry_pass =
                    String::from_utf8_lossy(&pass_ref[..pass_len]).to_string();

                let title_len = dec_metadata
                    .iter()
                    .position(|x| *x == 0)
                    .unwrap_or(dec_metadata.len());
                self.current_entry_title =
                    String::from_utf8_lossy(&dec_metadata[..title_len]).to_string();
            }

            egui::Grid::new("main_entry_grid")
                .num_columns(2)
                .spacing([0., 10.])
                .show(ui, |ui| {
                    ui.label("Title: ");
                    ui.label(self.current_entry_title.as_str());
                    ui.end_row();

                    ui.separator();
                    ui.separator();
                    ui.end_row();

                    ui.label("Username: ");
                    copy_text(ui, &self.current_entry_user, None);
                    ui.end_row();

                    ui.label("Password: ");
                    copy_text(
                        ui,
                        &self.current_entry_pass,
                        Some(&mut self.current_entry_show_pass),
                    );
                    ui.end_row();

                    if ui.button("Change").clicked() {
                        self.notifications.info("Change");
                        self.show_change_entry_window = true;
                        self.change_entry_title = self.current_entry_title.clone();
                        self.change_entry_user = self.current_entry_user.clone();
                        self.change_entry_pass = self.current_entry_pass.clone();
                        self.change_entry_idx = Some(entry_idx);
                    }
                    if ui.button("Delete").clicked() {
                        self.notifications.info("Delete");
                        if self
                            .send_action_request(Action::Delete { entry_idx })
                            .is_none()
                        {
                            self.notifications.error("Failed to delete the entry.");
                            return;
                        }
                        let Some(Response::Success) = self.read_action_response() else {
                            self.notifications.error("Failed to delete the entry.");
                            return;
                        };
                        self.notifications.info("Deleted entry.");
                        self.set_current_entry(None);
                        self.metadata.del_entry(entry_idx);
                    }
                    ui.end_row();
                });
        });
    }

    fn change_board(&mut self) {
        let board = serialport::new(self.board_port.as_str(), USART_BAUD)
            .open()
            .map(|mut serial| {
                serial.set_timeout(SERIAL_TIMEOUT).unwrap();
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
                self.notifications.error("Failed to establish shared key.");
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
        let sk = SecretKey::generate(&mut OsRng);
        if std::fs::write("demo.vault", format!("{sk}")).is_err() {
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

        let dec = decrypt_block(metadata, &self.vault_key?).ok()?;
        if let Some(zi) = dec.iter().position(|x| *x == 0) {
            Some(String::from_utf8_lossy(&dec[..zi]).to_string())
        } else {
            Some(String::from_utf8_lossy(&dec).to_string())
        }
    }
}

// nicked from:
// https://github.dev/numfin/pwd-manager/blob/main/gui/src/egui_app.rs#L14
fn copy_text(ui: &mut Ui, value: &str, secret: Option<&mut bool>) -> egui::InnerResponse<()> {
    egui::Frame::default().show(ui, |ui| {
        match secret {
            Some(false) => {
                ui.label(RichText::new("*".repeat(value.len())).monospace());
            }
            _ => {
                ui.label(RichText::new(value).monospace());
            }
        };
        if ui.button("copy").clicked() {
            ui.output_mut(|o| o.copied_text = value.to_owned());
        }
        if let Some(hide_secret) = secret {
            let toggle_label = match hide_secret {
                true => "hide",
                false => "show",
            };
            if ui.button(toggle_label).clicked() {
                *hide_secret = !*hide_secret;
            }
        }
    })
}
