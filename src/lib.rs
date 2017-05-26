
//! Utility functions related to xor encryption / decryption.
//!
//! Contains a mix bag of functions related to xor encryption / decryption.


#[macro_use]
extern crate log;

use std::io::Read;

pub trait Xor {
    /// Creates xor encrypted copy of data using the provided key.
    fn xor(&mut self, key_bytes : Vec<u8>) -> Vec<u8>;
}

fn xor(reader: &mut Read, key_bytes : Vec<u8>) -> Vec<u8> {
    let mut key_idx = 0;
    let mut warning_shown = false;
    let mut encoded_bytes: Vec<u8> = Vec::new();

    // Iterate each chunk of input data and XOR it against the provided key.
    loop {
        let mut data = [0; 1024];
        let num_read = reader.read(&mut data[..]).unwrap();

        if num_read == 0 {
            break;
        }

        let data_bytes = &data[0 .. num_read];

        for b in data_bytes {
            let k = key_bytes[key_idx];
            let e = b ^ k;

            encoded_bytes.push(e);

            key_idx += 1;

            if key_idx >= key_bytes.len() {
                key_idx = key_idx % key_bytes.len();

                if !warning_shown {
                    warning_shown = true;
                    warn!("Key wasn't long enough and had to be re-used to fully encode data, use a longer key to be secure.");
                }
            }
        }
    }

    encoded_bytes
}

impl<'a, R: Read> Xor for &'a mut R {
    fn xor(&mut self, key_bytes : Vec<u8>) -> Vec<u8> {
        xor(self, key_bytes)
    }
}

impl Xor for Read {
    fn xor(&mut self, key_bytes : Vec<u8>) -> Vec<u8> {
        xor(self, key_bytes)
    }
}


/// Generate all combinations of ASCII up to the supplied character length.
///
/// This can be used to get all the possible ASCII keys of a certain character length.
pub fn gen_ascii_keys(length : u32) -> Vec<String> {
    let mut keys : Vec<String> = Vec::new();
    let max = 128u32.pow(length);

    for i in 0..max {
        let mut value = i;
        let mut key = String::new();

        for j in (0..length).rev() {
            let digit = value / 128u32.pow(j);
            value = value - digit * 128u32.pow(j);
            key.push_str(format!("{}", (digit as u8) as char).as_str());
        }

        keys.push(key);
    }

    keys
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn xor_works() {

        // Data is twice as long as the key.
        let data : Vec<u8>  = vec![0b11111111u8, 0b11111111u8, 0b00001111u8, 0b10101010u8, 0b11111111u8, 0b11111111u8, 0b00001111u8, 0b10101010u8];
        let key : Vec<u8>   = vec![0b11111111u8, 0b00000000u8, 0b11110000u8, 0b01010101u8];

        let reader : &mut Read = &mut Cursor::new(data);

        let cipher = reader.xor(key);

        assert_eq!(0b00000000u8, cipher[0]);
        assert_eq!(0b11111111u8, cipher[1]);
        assert_eq!(0b11111111u8, cipher[2]);
        assert_eq!(0b11111111u8, cipher[3]);
        assert_eq!(0b00000000u8, cipher[4]);
        assert_eq!(0b11111111u8, cipher[5]);
        assert_eq!(0b11111111u8, cipher[6]);
        assert_eq!(0b11111111u8, cipher[7]);
    }

}
