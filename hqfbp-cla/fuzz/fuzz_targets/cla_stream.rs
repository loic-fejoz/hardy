#![no_main]

use libfuzzer_sys::fuzz_target;

use hardy_hqfbp_cla_fuzz::fuzz_kiss_and_hqfbp;

fuzz_target!(|data: &[u8]| {
    fuzz_kiss_and_hqfbp(data);
});
