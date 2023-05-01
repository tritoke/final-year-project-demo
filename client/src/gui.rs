use crate::auth::register_user;
use crate::{auth::establish_key, msg_receiver::MsgReceiver, Client, K1, USART_BAUD};
use aucpace::AuCPaceClient;
use chacha20poly1305::Key;
use eframe::egui;
use egui::{Align, Layout, Pos2, Rect, Ui, Vec2, Visuals};
use egui_extras::{Column, Table, TableBuilder};
use egui_notify::Toasts;
use rand_core::OsRng;
use serialport::{SerialPort, SerialPortType};
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
            State::Homepage => {
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
    }

    fn register(&mut self, ctx: &egui::Context) {
        debug!("Attempting to login as {}", self.user);
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
        self.login(ctx);
    }
}
