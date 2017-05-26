
//! Utility functions related to xor encryption / decryption.
//!
//! Contains a mix bag of functions related to xor encryption / decryption.

extern crate hamming;

#[macro_use]
extern crate log;

use std::io::Read;
use hamming::distance;
use std::collections::HashMap;

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

/// Calculates the average normalized hamming distance for the given input bytes
///
/// The average normalized hamming distance is calculated by
///
/// 1. Pick a keysize s
/// 2. Take 2 chunks each of size s
/// 3. Calculate the hamming distance between these 2 chunks
/// 4. Normalize the hamming distance by dividing by s
/// 5. Repeat 1-4 until there are no more chunks left
/// 6. Calculate the mean average of the normalized hamming distances calculated from the above.
///
/// Returns a HashMap that maps keysize to average normalized hamming distance for that keysize.
pub fn avg_normalized_hamming_distance(input : &Vec<u8>, max_keysize : usize) -> HashMap<usize, f32> {

    let mut keysize_to_avg_hamming_dist = HashMap::new();

    for keysize in 1..(max_keysize+1) {

        let mut chunks = input.chunks(keysize);
        let mut num_chunks_compared = 0;
        let mut average_hamming_dist = 0.0_f32;

        // Calculate the mean normalized hamming distance over a
        // number of samples to try to improve accuracy.
        loop {

            let left_chunk = chunks.next();
            let right_chunk = chunks.next();

            if left_chunk.is_none() {
                break;
            }
            if right_chunk.is_none() {
                break;
            }

            let left = left_chunk.unwrap();
            let right = right_chunk.unwrap();

            if left.len() != right.len() {
                break;
            }

            let hamming_dist = distance(left, right);
            let normalized_hamming = hamming_dist as f32 / keysize as f32;
            average_hamming_dist += normalized_hamming;

            debug!("{:4.3} is the normalized hamming distance for keysize {} and block {}", normalized_hamming, keysize, num_chunks_compared);

            num_chunks_compared += 1;
        }

        if num_chunks_compared != 0 {
            average_hamming_dist = average_hamming_dist / num_chunks_compared as f32;
            keysize_to_avg_hamming_dist.insert(keysize, average_hamming_dist);
        } else {
            debug!("Not enough data in input file to check a keysize of '{}'", keysize);
        }
    }

    keysize_to_avg_hamming_dist
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
