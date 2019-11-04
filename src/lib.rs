
//! Utility functions related to xor encryption / decryption.
//!
//! Contains a mix bag of functions related to xor encryption / decryption.

extern crate hamming;

#[macro_use]
extern crate log;

use std::io::{Read, BufReader};
use std::fs::File;
use hamming::distance;
use std::collections::HashMap;

pub trait Xor {
    /// Creates xor encrypted copy of data using the provided key.
    fn xor(&mut self, key_bytes : &[u8]) -> Vec<u8>;
}

fn xor<R: Read + ?Sized>(reader: &mut R, key_bytes : &[u8]) -> Vec<u8> {
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

impl<'a, R: Read + ?Sized> Xor for R {
    fn xor(&mut self, key_bytes : &[u8]) -> Vec<u8> {
        xor(self, key_bytes)
    }
}

pub trait Score {
    /// Calculates a relative value "score" for an item which relates to how likely it is the item
    /// represents text.
    ///
    /// This value can be used to determine the likeliness of the item representing text.
    fn score(&self) -> f32;
}

pub trait ScoreAgainstDictionary {
    /// Calculates a relative value "score" for an item which relates to how likely it is the item
    /// represents text.
    ///
    /// The provided words vector is used to increase the score of the item if it contained any of
    /// the words in the vector.
    fn score_with_words(&self, words_list : Vec<String>) -> f32;
}

impl Score for char {
    fn score(&self) -> f32 {
        score_character(*self)
    }
}

impl Score for String {
    fn score(&self) -> f32 {

        let expected_char_frequency = get_char_score_map();

        // Filter to only ascii characters that are contained in the expected char freq dict.
        // Uppercase is mapped to lowercase.
        let ascii_only_vector : Vec<u8> = self.chars()
            .filter(|c| c.is_ascii())
            .map(|c| c.to_ascii_lowercase())
            .filter(|c| expected_char_frequency.get(&c).is_some())
            .map(|c| c as u8)
            .collect();

        // String containing only the ascii parts of the input string.
        let ascii_only = String::from_utf8(ascii_only_vector).unwrap();
        debug!("Ascii only is: {}", ascii_only);

        let mut actual_char_frequency = HashMap::new();

        // Build the dict of actual char frequencies.
        for c in ascii_only.chars() {
            let count = actual_char_frequency.entry(c).or_insert(0.0);
            *count += 1.0;
        }
        for count in actual_char_frequency.values_mut() {
            *count = *count / ascii_only.len() as f32;
        }

        let mut sum = 0.0f32;

        for (c, freq) in actual_char_frequency {
            let expected = expected_char_frequency.get(&c).unwrap();
            let diff = (*expected - freq).abs() * 10.0;

            debug!("Diff for char '{}' is {}", c, diff);
            sum += diff;
        }

        let proportion_of_ascii = ascii_only.len() as f32 / self.len() as f32;

        sum = sum * proportion_of_ascii;

        sum
    }
}

impl ScoreAgainstDictionary for String {
    fn score_with_words(&self, words_list : Vec<String>) -> f32 {
        let mut sum = 0.0f32;

        // Score each character.
        sum += self.score();

        // Score each word.
        sum += score_words(self, words_list);

        sum
    }
}

/// Loads all lines in the given file and sorts them
///
/// Assumes the file is newline separated list of words.
pub fn load_words_list(path : &str) -> Vec<String> {

    // Will hold all the words in the dictionary file.
    let mut dictionary_lines : Vec<String> = Vec::new();

    match File::open(path) {
        Ok(file) => {
            // Read all the words and push them to the dictionary vector.
            let mut reader = BufReader::new(file);
            let mut dictionary_data = String::new();
            let _ = reader.read_to_string(&mut dictionary_data);

            for line in dictionary_data.lines() {
                let word = line.to_lowercase();
                dictionary_lines.push(word);
            }

            // Sort the dictionary in order of word length, largest words to smallest words.
            dictionary_lines.sort_by(|a, b| {
                let x = a.len();
                let y = b.len();

                y.cmp(&x)
            });
        },
        Err(err) => {
            println!("Failed to open dictionary file '{}' because: {:?}", path, err);
        }
    }

    dictionary_lines
}

fn recursive_add_keys(length: u32, prefix : Vec<u8>, keys : &mut Vec<String>) {
    if prefix.len() == (length as usize) {
        // Key has been generated
        let key = String::from_utf8(prefix).unwrap();
        keys.push(key);
    } else {
        for idx in 0..128 {
            let mut new_prefix = prefix.clone();
            new_prefix.push(idx);

            recursive_add_keys(length, new_prefix, keys);
        }
    }
}


/// Generate all combinations of ASCII up to the supplied character length.
///
/// This can be used to get all the possible ASCII keys of a certain character length.
pub fn gen_ascii_keys(length : u32) -> Vec<String> {
    let mut keys : Vec<String> = Vec::new();
    let prefix : Vec<u8> = Vec::new();

    recursive_add_keys(length, prefix, &mut keys);

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
        for _ in 1..3 {

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

fn score_words(words : &String, dictionary : Vec<String>) -> f32 {
    let mut score : f32 = 0.0;

    // Check if the input contains a word from the dictionary.
    // Each time a word is matched it's removed from the input so there isn't double
    // counting of words.
    //
    // For each word the score is increased by 3 * e ^ word_length.
    // In this way large words contribute exponentially more to the overall score.
    let mut cloned_input = words.clone();
    for word in dictionary {
        if cloned_input.contains(word.as_str()) {
            let adjustment = 3.0 * (word.len() as f32).exp();
            score = score + adjustment;

            cloned_input = cloned_input.replacen(word.as_str(), "", 1);
        }
    }

    score
}


fn score_character(c : char) -> f32 {
    let character_scores = get_char_score_map();

    if character_scores.contains_key(&c) {
        let value = character_scores.get(&c).unwrap();
        *value
    } else {
        0.00
    }
}

// Creates a dictionary where:
// key      - character
// value    - frequency score
fn get_char_score_map() -> HashMap<char, f32> {
    let mut character_scores = HashMap::new();

    character_scores.insert(' ', 15.000); // This is just guessed
    character_scores.insert('e', 12.702);
    character_scores.insert('t', 9.056);
    character_scores.insert('a', 8.167);
    character_scores.insert('o', 7.507);
    character_scores.insert('i', 6.966);
    character_scores.insert('n', 6.749);
    character_scores.insert('s', 6.327);
    character_scores.insert('h', 6.094);
    character_scores.insert('r', 5.987);
    character_scores.insert('d', 4.253);
    character_scores.insert('l', 4.025);
    character_scores.insert('c', 2.782);
    character_scores.insert('u', 2.758);
    character_scores.insert('m', 2.406);
    character_scores.insert('w', 2.360);
    character_scores.insert('f', 2.228);
    character_scores.insert('g', 2.015);
    character_scores.insert('y', 1.974);
    character_scores.insert('p', 1.929);
    character_scores.insert('b', 1.492);
    character_scores.insert('v', 0.978);
    character_scores.insert('k', 0.772);
    character_scores.insert('j', 0.153);
    character_scores.insert('x', 0.150);
    character_scores.insert('q', 0.095);
    character_scores.insert('z', 0.074);

    character_scores
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

        let mut reader = Cursor::new(data);

        let cipher = reader.xor(&key);

        assert_eq!(0b00000000u8, cipher[0]);
        assert_eq!(0b11111111u8, cipher[1]);
        assert_eq!(0b11111111u8, cipher[2]);
        assert_eq!(0b11111111u8, cipher[3]);
        assert_eq!(0b00000000u8, cipher[4]);
        assert_eq!(0b11111111u8, cipher[5]);
        assert_eq!(0b11111111u8, cipher[6]);
        assert_eq!(0b11111111u8, cipher[7]);
    }

    #[test]
    fn scoring_strings_works() {
        let a = String::from("hello world");
        let b = String::from("9[;,1.23,45");
        let c = String::from("$*(&^$@!as3");
        let d = String::from("kj12asd89hh");

        let score_a = a.score();
        let score_b = b.score();
        let score_c = c.score();
        let score_d = d.score();

        assert!(score_a > score_b);
        assert!(score_a > score_c);
        assert!(score_a > score_d);
    }

}
