// jwt_decoder.rs
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use clap::{App, Arg};
use base64::decode_config;
use base64::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use chrono::{DateTime, Utc};

type HmacSha256 = Hmac<Sha256>;

struct JWT {
    token: String,
    key: Option<String>,
    header: Value,
    payload: Value,
    signature: String,
    valid_signature: Option<bool>,
    expired: Option<bool>,
}

impl JWT {
    fn new(token: String, key: Option<String>) -> Self {
        JWT { token, key, header: Value::Null, payload: Value::Null, signature: String::new(), valid_signature: None, expired: None }
    }

    fn decode(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".into());
        }

        // Decode header
        let header_bytes = decode_config(parts[0], URL_SAFE_NO_PAD)?;
        self.header = serde_json::from_slice(&header_bytes)?;

        // Decode payload
        let payload_bytes = decode_config(parts[1], URL_SAFE_NO_PAD)?;
        self.payload = serde_json::from_slice(&payload_bytes)?;

        self.signature = parts[2].to_string();

        // Check expiration
        if let Some(exp_val) = self.payload.get("exp") {
            if let Some(exp) = exp_val.as_u64() {
                let exp_time = DateTime::<Utc>::from_timestamp(exp as i64, 0).unwrap_or_default();
                self.expired = Some(Utc::now() > exp_time);
            }
        }

        // Verify signature
        if let Some(ref key) = self.key {
            self.valid_signature = Some(self.verify_signature(key)?);
        }

        Ok(())
    }

    fn verify_signature(&self, key: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = self.token.split('.').collect();
        let data = format!("{}.{}", parts[0], parts[1]);
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())?;
        mac.update(data.as_bytes());
        let sig_bytes = mac.finalize().into_bytes();
        let sig_b64 = base64::encode_config(sig_bytes, URL_SAFE_NO_PAD);
        Ok(sig_b64 == parts[2])
    }

    fn to_json(&self) -> Value {
        let mut map = json!({
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature,
            "token": self.token,
        });
        if let Some(v) = self.valid_signature { map["valid_signature"] = json!(v); }
        if let Some(v) = self.expired { map["expired"] = json!(v); }
        map
    }

    fn print(&self, color: bool) {
        if color {
            println!("\x1b[32mHeader:\x1b[0m");
            for (k, v) in self.header.as_object().unwrap() {
                println!("  {}: {}", k, v);
            }
            println!("\x1b[33mPayload:\x1b[0m");
            for (k, v) in self.payload.as_object().unwrap() {
                println!("  {}: {}", k, v);
            }
            if let Some(exp) = self.expired {
                if exp {
                    println!("\x1b[31m  ✗ Token expired\x1b[0m");
                } else {
                    println!("\x1b[32m  ✓ Token valid\x1b[0m");
                }
            }
            if let Some(valid) = self.valid_signature {
                if valid {
                    println!("\x1b[32m  ✓ Signature verified\x1b[0m");
                } else {
                    println!("\x1b[31m  ✗ Signature invalid\x1b[0m");
                }
            }
            println!("\x1b[36mSignature: {}\x1b[0m", self.signature);
        } else {
            println!("Header:");
            for (k, v) in self.header.as_object().unwrap() {
                println!("  {}: {}", k, v);
            }
            println!("Payload:");
            for (k, v) in self.payload.as_object().unwrap() {
                println!("  {}: {}", k, v);
            }
            if let Some(exp) = self.expired {
                println!("  Token {}", if exp { "expired" } else { "valid" });
            }
            if let Some(valid) = self.valid_signature {
                println!("  Signature {}", if valid { "verified" } else { "invalid" });
            }
            println!("Signature: {}", self.signature);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("JWT Decoder")
        .arg(Arg::with_name("token").index(1).help("JWT token"))
        .arg(Arg::with_name("key").long("key").takes_value(true).help("Secret key for HMAC"))
        .arg(Arg::with_name("file").long("file").takes_value(true).help("Read JWT from file"))
        .arg(Arg::with_name("json").long("json").help("Output as JSON"))
        .arg(Arg::with_name("color").long("color").help("Force color output"))
        .get_matches();

    let mut token = matches.value_of("token").map(String::from);
    if let Some(file) = matches.value_of("file") {
        token = Some(fs::read_to_string(file)?.trim().to_string());
    }
    if token.is_none() && !atty::is(atty::Stream::Stdin) {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        token = Some(s.trim().to_string());
    }
    if token.is_none() {
        eprintln!("Error: no token provided");
        std::process::exit(1);
    }

    let key = matches.value_of("key").map(String::from);
    let mut jwt = JWT::new(token.unwrap(), key);
    if let Err(e) = jwt.decode() {
        eprintln!("Error decoding JWT: {}", e);
        std::process::exit(1);
    }

    if matches.is_present("json") {
        println!("{}", serde_json::to_string_pretty(&jwt.to_json())?);
    } else {
        let color = matches.is_present("color") || atty::is(atty::Stream::Stdout);
        jwt.print(color);
    }
    Ok(())
}
