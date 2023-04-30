use crate::USART_BAUD;
use eframe::egui;
use egui::Key::S;
use egui::{Align, Layout, Pos2, Rect, Ui, Vec2, Visuals};
use egui_extras::{Column, Table, TableBuilder};
use serialport::{SerialPort, SerialPortType};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub struct Gui {
    state: State,
    user: String,
    pass: String,
    board_port: String,
    board: Option<Arc<Mutex<Box<dyn SerialPort>>>>,
}

impl Default for Gui {
    fn default() -> Self {
        let board = serialport::new("/dev/ttyACM0", USART_BAUD)
            .open()
            .ok()
            .map(|serial| Arc::new(Mutex::new(serial)));

        Self {
            state: State::default(),
            user: String::default(),
            pass: String::default(),
            board_port: String::from("/dev/ttyACM0"),
            board,
        }
    }
}

#[derive(Default)]
enum State {
    #[default]
    Login,
}

impl eframe::App for Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("app_top_bar").show(ctx, |ui| {
            self.board_dropdown(ui);
        });
        egui::CentralPanel::default().show(ctx, |ui| match &mut self.state {
            State::Login => self.login_screen(ui),
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
            .map(|serial| Arc::new(Mutex::new(serial)));

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
                                    self.login();
                                }
                            });
                            row.col(|ui| {
                                if ui.button("Register").clicked() {
                                    self.register();
                                }
                            });
                        });
                    });
            });
        });
    }

    fn login(&mut self) {
        info!("Login");
        todo!("login");
    }

    fn register(&mut self) {
        info!("Register");
        todo!("register");
        self.login();
    }
}
