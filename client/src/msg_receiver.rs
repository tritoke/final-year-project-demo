use crate::{K1, RECV_BUF_LEN};
use aucpace::ServerMessage;
use serde::Deserialize;
use serialport::SerialPort;
use std::sync::Mutex;
use tracing::{trace, warn};

pub struct MsgReceiver<'mtx> {
    buf: [u8; RECV_BUF_LEN],
    idx: usize,
    mtx: &'mtx Mutex<Box<dyn SerialPort>>,
    reset_pos: Option<usize>,
}

impl<'mtx> MsgReceiver<'mtx> {
    pub fn new(mtx: &'mtx Mutex<Box<dyn SerialPort>>) -> Self {
        Self {
            buf: [0u8; 1024],
            idx: 0,
            mtx,
            reset_pos: None,
        }
    }

    pub fn recv_msg<'a, T: Deserialize<'a>>(&'a mut self) -> postcard::Result<T> {
        // reset the state
        // copy all the data we read after the 0 byte to the start of the self.buffer
        if let Some(zi) = self.reset_pos {
            self.buf.copy_within(zi + 1..self.idx, 0);
            self.idx = self.idx.saturating_sub(zi + 1);
            self.reset_pos = None;
        }

        // acquire a handle to the serial port
        let mut serial = self
            .mtx
            .lock()
            .expect("Failed to acquire lock for serial port.");

        loop {
            // read as much as we can off the wire
            let count = serial
                .read(&mut self.buf[self.idx..])
                .expect("Failed to read from serial port.");
            let zero_idx = if count == 0 {
                continue;
            } else {
                // log that we managed to read some data
                trace!(
                    "Read {} bytes - {:02X?}",
                    count,
                    &self.buf[self.idx..self.idx + count]
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

            self.reset_pos = Some(zi);
            // parse the result
            break postcard::from_bytes_cobs(&mut self.buf[..=zi]);
        }
    }
}
