// SecretExchange: Exchange secrets between processes in an unexposed way.

// Initial C implementation: https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/gcr-secret-exchange.c

// The initial implementation of SecretExchange/GCRSecretExchange uses a KeyFile
// to encode/parse the payload. And in this implementation the payload is based
// on a HashMap.
// Before any transit operations the payload is base64 encoded and parsed into a
// String.

use std::collections::HashMap;

use base64::prelude::*;
use cipher::{
    block_padding::{AnsiX923, Iso10126, Iso7816, NoPadding, Pkcs7, ZeroPadding},
    BlockDecryptMut, KeyIvInit,
};
use hkdf::Hkdf;
use oo7::{crypto, Key};
use sha2::Sha256;
use zeroize::Zeroizing;

const SECRET: &str = "secret";
const PUBLIC: &str = "public";
const PRIVATE: &str = "private";
const IV: &str = "iv";
const PROTOCOL: &str = "[sx-aes-1]\n";
const CIPHER_TEXT_LEN: usize = 16;
const IV_LEN: usize = 16;

#[derive(Debug)]
pub struct SecretExchange {
    private_key: Key,
    public_key: Key,
}

impl SecretExchange {
    // Creates the initial payload containing caller public_key
    pub fn begin(&self) -> String {
        let map = HashMap::from([(PUBLIC, self.public_key.as_ref())]);

        encode(&map)
    }

    // Creates the shared secret: an AES key
    pub fn create_shared_secret(&self, exchange: &str) -> String {
        let decoded = decode(exchange).unwrap();
        let public_key = Key::new(decoded.get(PUBLIC).unwrap().to_vec());
        let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
        let map = HashMap::from([(PRIVATE, aes_key.as_ref())]);

        encode(&map)
    }

    // Decrypt and retrieve secret
    pub fn receive(&self, exchange: &str) -> String {
        let decoded = decode(exchange).unwrap();
        let mut encrypted: Vec<u8> = Vec::new();
        let mut map: HashMap<&str, &[u8]> = HashMap::new();

        let secret = decoded.get(SECRET);
        if secret.is_some() {
            let secret = secret.unwrap();
            let public_key = Key::new(decoded.get(PUBLIC).unwrap().to_vec());
            let iv = decoded.get(IV).unwrap();

            let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
            encrypted = crypto::decrypt(secret, &aes_key, &iv).to_vec();

            map.insert(SECRET, &encrypted);
        }
        map.insert(PUBLIC, self.public_key.as_ref());

        encode(&map)
    }

    // Send Secret and perform encryption
    pub fn send(&self, secret: &str, exchange: &str) -> String {
        let decoded = decode(exchange).unwrap();

        let public_key = Key::new(decoded.get(PUBLIC).unwrap().to_vec());
        let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
        let iv = crypto::generate_iv();

        let secret = crypto::encrypt(secret, &aes_key, &iv);

        let map = HashMap::from([
            (PUBLIC, self.public_key.as_ref()),
            (SECRET, secret.as_ref()),
            (IV, iv.as_ref()),
        ]);

        encode(&map)
    }

    pub fn new() -> Self {
        let private_key = Key::generate_private_key();
        let public_key = Key::generate_public_key(&private_key);

        Self {
            private_key,
            public_key,
        }
    }
}

// Convert a HashMap into a payload String
fn encode(map: &HashMap<&str, &[u8]>) -> String {
    let mut exchange = map
        .iter()
        .map(|(k, v)| format!("{}={}", k, BASE64_STANDARD.encode(v)))
        .collect::<Vec<_>>()
        .join("\n");
    exchange.insert_str(0, PROTOCOL); // to add PROTOCOL prefix

    exchange
}

// Convert a payload String into a HashMap
fn decode(exchange: &str) -> Result<HashMap<&str, Vec<u8>>, base64::DecodeError> {
    let (_, exchange) = exchange.split_once(PROTOCOL).unwrap(); // to remove PROTOCOL prefix
    let pairs = exchange.split("\n").collect::<Vec<_>>();
    let mut map: HashMap<&str, Vec<u8>> = HashMap::new();
    let mut encoded: Vec<u8> = Vec::new();

    for pair in pairs {
        if pair.is_empty() {
            // to avoid splitting an empty line (last new line)
            break;
        }
        let (key, value) = pair.split_once("=").unwrap();
        encoded = BASE64_STANDARD.decode(value)?;
        map.insert(key, encoded);
    }

    Ok(map)
}

// Retrieve secret from the payload
pub fn get_secret(exchange: &str) -> Result<String, std::str::Utf8Error> {
    let decoded = decode(&exchange).unwrap();
    let secret = std::str::from_utf8(&decoded.get(SECRET).unwrap().to_vec())?
        .to_string()
        .to_owned();

    Ok(secret)
}

type DecAlg = cbc::Decryptor<aes::Aes128>;

pub(crate) fn decrypt(blob: impl AsRef<[u8]>, key: &Key, iv: impl AsRef<[u8]>) -> Vec<u8> {
    let mut data = blob.as_ref().to_vec();

    let decrypted = match DecAlg::new_from_slices(key.as_ref(), iv.as_ref())
        .expect("Invalid key length")
        .decrypt_padded_mut::<Pkcs7>(&mut data)
    {
        Ok(mat) => mat.to_vec(),
        Err(err) => panic!("decrypt_padded_mut failed: {err}"),
    };

    decrypted
}

pub fn retrieve_secret(exchange: &str, key: &str) -> Vec<u8> {
    // wip: not ready
    let decoded_exchange = decode(exchange).unwrap();
    let secret = decoded_exchange.get(SECRET).unwrap();
    let iv = decoded_exchange.get(IV).unwrap();
    // let public_key = Key::new(decoded_exchange.get(PUBLIC).unwrap().to_vec());

    let decoded_key = decode(key).unwrap();
    let aes_key = Key::new(decoded_key.get(PRIVATE).unwrap().to_vec());

    // let mut okm = [0u8; 16];
    //
    // let hk = Hkdf::<Sha256>::from_prk(&public_key).unwrap();
    // hk.expand(&context, &mut okm).unwrap();
    //
    // let dec_key = Key::new(okm.to_vec());

    // todo: return errors instead
    if iv.len() != IV_LEN {
        panic!("Invalid IV");
    }

    if secret.len() != CIPHER_TEXT_LEN {
        panic!("Invalid length for cipher text");
    }

    println!("looks good");

    decrypt(secret, &aes_key, iv)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secret_exchange() {
        let secret = "password";
        let caller = SecretExchange::new();
        let callee = SecretExchange::new();
        let exchange = caller.begin();
        let exchange = caller.receive(&exchange);
        let exchange = callee.send(secret, &exchange);
        let exchange = caller.receive(&exchange);

        assert_eq!(get_secret(&exchange).unwrap(), secret);
    }

    #[test]
    fn test_secret_retrieve() {
        let exchange_pub = "[sx-aes-1]
public=7dQuTAGl2AtbNpWYhn0Z9cWIQtHAGaxlDLCFGqSrGUikNZUgFCqBkn445TsxX0meX295NSmkslcSFr67dB/1H0jX+P//beTO+3ASTx7nD79Wb9Gc3Y2+yIKYmc7vDAj1kTGWiuBnfbshBbHlHbjnwiwGpKip+FtHlW9tzfGMkicM6wCV2hrXWB2zTdX6TkA8F+hhMRfcV4oB7gtgWITSofGhUubN1ablrsOb9V4dTMemvOmHZxMrJrTkVkJSQaED";

        let secret_exchange = "[sx-aes-1]
public=7dQuTAGl2AtbNpWYhn0Z9cWIQtHAGaxlDLCFGqSrGUikNZUgFCqBkn445TsxX0meX295NSmkslcSFr67dB/1H0jX+P//beTO+3ASTx7nD79Wb9Gc3Y2+yIKYmc7vDAj1kTGWiuBnfbshBbHlHbjnwiwGpKip+FtHlW9tzfGMkicM6wCV2hrXWB2zTdX6TkA8F+hhMRfcV4oB7gtgWITSofGhUubN1ablrsOb9V4dTMemvOmHZxMrJrTkVkJSQaED
secret=Ikp4HxUANjnJQILgf/XCmg==
iv=zJbGXyat1z2tpDcMVofXRA==";

        let oo7_public_key = "[sx-aes-1]
public=xlVMthdNadaSAKPN7NsWPOZcUa4skSiMst3lR9RUl7uLTmyI4GMmT9RGV8ggdPpEBnWfV6yHg5UWJEXIZP3n8FSerB1/bcVjHUk7lUmFqvDlNrqRDVsYxJhMkYYLSd0I+FGpCy5aferX/0q6r3tl36T/rZChzGE1lq2I0qAEUww=";

        let oo7_private_key = "[sx-aes-1]
private=YMFltkVd3OaeBmqyir+9kA==";

        let oo7_exchange_aes = "[sx-aes-1]
private=EzfHZg70ZpqHjuoMHGN2rg==";

        let decrypted = retrieve_secret(secret_exchange, oo7_exchange_aes);
        assert_eq!(b"password".to_vec(), decrypted);
    }
}
