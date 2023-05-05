use defmt::{trace, unwrap, warn};
use embassy_stm32::peripherals;
use embassy_stm32::usart::UartRx;
use serde::Deserialize;

const RECV_BUF_LEN: usize = 1024;

pub struct MsgReceiver<'uart> {
    buf: [u8; RECV_BUF_LEN],
    idx: usize,
    rx: UartRx<'uart, peripherals::USART2, peripherals::DMA1_CH5>,
    reset_pos: Option<usize>,
    cobs_decode_end: Option<usize>,
    reparse_message: bool,
}

impl<'uart> MsgReceiver<'uart> {
    pub fn new(rx: UartRx<'uart, peripherals::USART2, peripherals::DMA1_CH5>) -> Self {
        Self {
            buf: [0u8; 1024],
            idx: 0,
            rx,
            reset_pos: None,
            cobs_decode_end: None,
            reparse_message: false,
        }
    }

    pub async fn recv_msg<'a, T: Deserialize<'a>>(&'a mut self) -> postcard::Result<T> {
        if self.reparse_message {
            self.reparse_message = false;
            if let Some(cde) = self.cobs_decode_end {
                return postcard::from_bytes(&self.buf[..cde]);
            }
        }

        // reset the state
        // copy all the data we read after the 0 byte to the start of the self.buffer
        if let Some(zi) = self.reset_pos {
            self.buf.copy_within(zi + 1..self.idx, 0);
            self.idx = self.idx.saturating_sub(zi + 1);
            self.reset_pos = None;
            self.cobs_decode_end = None;
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

        // manually decode from COBS so we know where the valid data is
        let cde = cobs::decode_in_place(&mut self.buf[..=zi])
            .map_err(|_| postcard::Error::DeserializeBadEncoding)?;

        self.cobs_decode_end = Some(cde);

        // parse the result
        postcard::from_bytes(&self.buf[..cde])
    }

    pub fn unparse_last_message(&mut self) {
        self.reparse_message = true;
    }
}
