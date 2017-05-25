
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

impl Xor for Read {
    fn xor(&mut self, key_bytes : Vec<u8>) -> Vec<u8> {

        let mut key_idx = 0;
        let mut warning_shown = false;
        let mut encoded_bytes: Vec<u8> = Vec::new();

        // Iterate each chunk of input data and XOR it against the provided key.
        loop {
            let mut data = [0; 1024];
            let num_read = self.read(&mut data[..]).unwrap();

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

        let mut input = Cursor::new(data);
        let mut reader = &mut input as &mut Read;

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
