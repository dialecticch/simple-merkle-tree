use std::{collections::HashMap, io::Read, ops::Index};

use tiny_keccak::Hasher;

type Buffer = Vec<u8>;
type Data = [u8; 32];
type Hash = [u8; 32];

type BufferHash = String;
pub struct MerkleTree {
    hashed_elements: Vec<Hash>,
}

impl MerkleTree {
    pub fn new(elements: Vec<Buffer>) -> Self {
        let elements = {
            let mut elements: Vec<Buffer> = elements
                .into_iter()
                // Filter empty
                .filter(|e| !e.iter().all(|e| *e == 0))
                .collect();

            // Sort
            elements.sort();

            // Deduplicate
            let el_len = elements.len();
            let elements = elements
                .into_iter()
                .fold(Vec::with_capacity(el_len), |mut acc, i| {
                    if !acc.contains(&i) {
                        acc.push(i);
                    }
                    acc
                });
            elements
        };

        // Construct hashes
        let el_len = elements.len();
        let (capacity, levels) = MerkleTree::calculate_levels(&el_len);

        let vector_size = 2 * el_len - 1;
        let mut result = vec![[0; 32]; vector_size];
        log::debug!("Creating a vector with size {:}", vector_size);

        let mut prior_elements = 0;
        for level in 1..=levels {
            let elem_count_in_level = el_len / level as usize;
            let start_index = capacity - prior_elements - elem_count_in_level;

            let end_index = start_index + elem_count_in_level; // non inclusive
            prior_elements += elem_count_in_level;
            log::debug!("start_index: {}| end_index {}| elem_count_in_level {}", start_index, end_index, elem_count_in_level);

            if level == 1 {
                for (idx, elem) in elements.iter().enumerate() {
                    let hashed = MerkleTree::hash(&elem);
                    result[start_index + idx] = hashed;
                }
            } else {
                for idx in start_index..end_index {
                    let left = (2_usize * idx) + 1;
                    let right = (2_usize * idx) + 2;

                    log::debug!("Getting child of {}| L: {}| R: {}", start_index + idx, left, right);
                    let left = result[left];
                    let right = result[right];
                    let parent = MerkleTree::combined_hash(&left, &right);
                    result[start_index + idx] = parent;
                }
            }
        }

        log::debug!("Constructed merkle tree {:?}", &result);
        Self {
            hashed_elements: result,
        }
    }

    fn combined_hash(first:  &[u8], second:  &[u8]) -> [u8; 32] {
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(first);
        keccak.update(second);
        let mut result: [u8; 32] = Default::default();
        keccak.finalize(&mut result);
        result
    }

    fn get_root(&self) -> &[u8; 32] {
        &self.hashed_elements[0]
    }

    // fn get_proof(&self, el: Buffer) -> &Vec<Buffer> {
    //     let index = *self.elements.fin(el);

    //     self.layers.iter().fold(vec![], |acc, layer| {
    //         let pair_element = {
    //             // let pair_index =
    //         };
    //     });

    //     todo!()
    // }
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&data);
        let mut result: [u8; 32] = Default::default();
        keccak.finalize(&mut result);
        result
    }

    fn calculate_levels(el_len: &usize) -> (usize, u32) {
        let capacity = 2 * el_len - 1;
        let levels: u32 = ((capacity as f32).log2() + 1.) as u32;
        (capacity, levels)
    }

}

#[cfg(test)]
mod tests {

    use super::*;

    fn generate_sample_vec(items: u32) -> Vec<Vec<u8>> {
        let elements = (0..items)
            .map(|el| format!("item-string-{:}", el).into_bytes())
            .collect::<Vec<Vec<u8>>>();
        elements
    }

    #[test]
    fn construct_tree() {
        simple_logger::init_with_level(log::Level::Debug).unwrap();
        let elements = generate_sample_vec(4);
        let levels = MerkleTree::new(elements);
    }

    #[test]
    fn levels_get_calculated() {
        let elements = generate_sample_vec(4);
        let levels = MerkleTree::calculate_levels(&elements.len());
        assert_eq!(levels, (7, 3));
    }
    #[test]
    fn levels_get_calculated_v2() {
        let elements = generate_sample_vec(3);
        let levels = MerkleTree::calculate_levels(&elements.len());
        assert_eq!(levels, (5, 3));
    }
    #[test]
    fn levels_get_calculated_v3() {
        let elements = generate_sample_vec(2);
        let levels = MerkleTree::calculate_levels(&elements.len());
        assert_eq!(levels, (3, 2));
    }
}
