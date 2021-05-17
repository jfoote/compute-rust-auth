use std::collections::HashMap;

const COOKIE_ATTRIBUTES: &str = "Path=/; SameSite=Lax; Secure; HttpOnly";
const COOKIE_PREFIX: &str = "__Secure-";

pub fn parse(cookie_string: &str) -> HashMap<&str, &str> {
    cookie_string
        .split("; ")
        .filter_map(|kv| {
            kv.find('=').map(|index| {
                let (key, value) = kv.split_at(index);
                let mut key = key.trim();
                if key.starts_with(&COOKIE_PREFIX) {
                    key = &key[..(key.len() - COOKIE_PREFIX.len())];
                }
                let value = value[1..].trim();
                (key, value)
            })
        })
        .collect()
}

pub fn persistent(name: &str, value: &str, max_age: u32) -> String {
    format!(
        "{}-{}={}; Max-Age={}; {}",
        COOKIE_PREFIX, name, value, max_age, COOKIE_ATTRIBUTES
    )
}

pub fn expired(name: &str) -> String {
    persistent(name, "expired", 0)
}

pub fn session(name: &str, value: &str) -> String {
    format!(
        "{}-{}={}; {}",
        COOKIE_PREFIX, name, value, COOKIE_ATTRIBUTES
    )
}

/*
#[cfg(test)]
use quickcheck::quickcheck; // Rust 2018 style
use cookie::Cookie;
*/

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck::quickcheck! {
        fn cookie_parsers_agree(cookie_string: String) -> bool {
            let fastly_cookie = parse(&cookie_string);
            match cookie::Cookie::parse(cookie_string.clone()) {
                Err(cookie::ParseError::EmptyName) => match fastly_cookie.get("") {
                    Some(_) => true,
                    None => false
                },
                Err(_) => fastly_cookie.is_empty(),
                Ok(cookie) => fastly_cookie.get(cookie.name()).unwrap() == &cookie.value()
            }
        }
    }

    #[test]
    fn test_fail() {
        // Demo to show input when a property test fails
        let cookie_string = "\u{0}=;";
        let fastly_cookie = parse(&cookie_string);
        println!("fastly_cookie={:?}", fastly_cookie);
        let cookie_result = cookie::Cookie::parse(cookie_string.clone());
        println!("cookie={:?}", cookie_result);
        let cookie = cookie_result.unwrap();
        println!("cooke.name={:?}, cookie.value={:?}", cookie.name(), cookie.value());
        assert!(true);
    }
}
