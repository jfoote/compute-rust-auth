#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate compute_rust_auth;

use jwt_simple::claims::NoCustomClaims;
use compute_rust_auth::jwt::validate_token_rs256;
use compute_rust_auth::config::Config;

fuzz_target!(|data: &[u8]| {

    let settings = Config::load();
    if let Ok(id_token) = std::str::from_utf8(data) {
        let _ = validate_token_rs256::<NoCustomClaims>(id_token, &settings);
    }
});
