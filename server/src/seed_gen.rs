use embassy_stm32::adc::{Adc, Temperature};
use embassy_stm32::peripherals::ADC1;
use embassy_time::{Delay, Instant};

// an attempt at generating some entropy / non repeating values
pub struct SeedGenerator<'adc> {
    adc: Adc<'adc, ADC1>,
    temp_channel: Temperature,
}

impl<'adc> SeedGenerator<'adc> {
    pub fn new(adc_peripheral: ADC1) -> Self {
        let adc = Adc::new(adc_peripheral, &mut Delay);
        let temp_channel = adc.enable_temperature();
        Self { adc, temp_channel }
    }

    pub fn gen_seed(&mut self) -> u64 {
        let now = Instant::now().as_ticks();
        let temp = self.adc.read_internal(&mut self.temp_channel) as u64;
        now ^ (temp << 48)
    }
}
