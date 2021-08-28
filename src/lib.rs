use std::fmt::Debug;

pub use tiny_keccak::Hasher;

pub type Buffer = Vec<u8>;
type Hash = [u8; 32];

pub struct MerkleTree {
    hashed_elements: Vec<Hash>,
}

// Public interface impl
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
            log::trace!(
                "start_index: {}| end_index {}| elem_count_in_level {}",
                start_index,
                end_index,
                elem_count_in_level
            );

            if level == 1 {
                for (idx, elem) in elements.iter().enumerate() {
                    let hashed = MerkleTree::hash(&elem);
                    log::trace!(
                        "Setting idx {:} to {:}",
                        start_index + idx,
                        hex::encode(hashed)
                    );
                    result[start_index + idx] = hashed;
                }
            } else {
                for idx in start_index..end_index {
                    let left = (2_usize * idx) + 1;
                    let right = (2_usize * idx) + 2;

                    log::trace!("Getting child of {}| L: {}| R: {}", idx, left, right);
                    let left = result[left];
                    let right = result[right];
                    let parent = MerkleTree::combined_hash(&left, &right);
                    // log::trace!("Setting idx {:} to {:}", start_index + idx, hex::encode(parent));
                    result[idx] = parent;
                }
            }
        }

        let res = Self {
            hashed_elements: result,
        };
        log::debug!("Constructed merkle tree {:#?}", &res);
        res
    }


    pub fn get_root(&self) -> &[u8; 32] {
        &self.hashed_elements[0]
    }

    pub fn get_proof(&self, el: &Buffer) -> Option<Vec<&[u8; 32]>> {
        let hashed = MerkleTree::hash(&el);
        log::debug!("Finding proof for {:}", hex::encode(hashed));

        let index = self.hashed_elements.iter().position(|e| e == &hashed);

        match index {
            Some(mut index) => {
                let mut res = vec![];

                while index > 0 {
                    // Skip the root element
                    let sibling = self.get_pair_element(index);

                    if let Some(sibling) = sibling {
                        log::trace!(
                            "getting pair elem for index {:}; res {:}",
                            index,
                            hex::encode(sibling)
                        );
                        res.push(sibling);
                    }

                    index = MerkleTree::calculate_parent_idx(index);
                    log::trace!("Parent {:}", index);
                }
                Some(res)
            }
            None => None,
        }
    }

}

// Private helper impl
impl MerkleTree {

    fn combined_hash(first: &[u8], second: &[u8]) -> [u8; 32] {
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(first);
        keccak.update(second);
        let mut result: [u8; 32] = Default::default();
        keccak.finalize(&mut result);
        result
    }

    fn get_pair_element(&self, idx: usize) -> Option<&[u8; 32]> {
        let pair_idx = MerkleTree::calculate_sibling_idx(idx);

        if pair_idx < self.hashed_elements.len() {
            return Some(&self.hashed_elements[pair_idx]);
        }
        return None;
    }

    fn calculate_sibling_idx(idx: usize) -> usize {
        if idx % 2 == 0 {
            idx - 1
        } else {
            idx + 1
        }
    }

    fn calculate_parent_idx(child_idx: usize) -> usize {
        let child_offset = {
            if child_idx % 2 == 0 {
                // If is right child
                2
            } else {
                // If is left child
                1
            }
        };

        (child_idx - child_offset) / 2
    }

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

impl Debug for MerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hashed_elements: Vec<String> = self
            .hashed_elements
            .iter()
            .map(|e| hex::encode(e))
            .collect();

        f.debug_struct("MerkleTree")
            .field("hashed_elements", &hashed_elements)
            .finish()
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
        simple_logger::init_with_level(log::Level::Trace).unwrap();
        let elements = generate_sample_vec(4);
        let tree = MerkleTree::new(elements.clone());

        let a = &elements[0];
        let b = &elements[1];
        let c = &elements[2];
        let d = &elements[3];

        let h_a = MerkleTree::hash(a);
        let h_b = MerkleTree::hash(b);
        let h_c = MerkleTree::hash(c);
        let h_d = MerkleTree::hash(d);

        let h_ab = MerkleTree::combined_hash(&h_a, &h_b);
        let h_cd = MerkleTree::combined_hash(&h_c, &h_d);

        let h_abcd = MerkleTree::combined_hash(&h_ab, &h_cd);

        log::debug!("h_abcd = {:}", hex::encode(h_abcd));

        log::debug!("h_ab = {:}", hex::encode(h_ab));
        log::debug!("h_cd = {:}", hex::encode(h_cd));

        log::debug!("h_a = {:}", hex::encode(h_a));
        log::debug!("h_b = {:}", hex::encode(h_b));
        log::debug!("h_c = {:}", hex::encode(h_c));
        log::debug!("h_d = {:}", hex::encode(h_d));

        {
            let proof = tree.get_proof(d).unwrap();
            assert_eq!(proof.len(), 2);

            assert_eq!(
                vec![hex::encode(h_c), hex::encode(h_ab),],
                proof
                    .iter()
                    .map(|e| hex::encode(e))
                    .collect::<Vec<String>>()
            );
        }

        {
            let proof = tree.get_proof(a).unwrap();
            assert_eq!(proof.len(), 2);

            assert_eq!(
                vec![hex::encode(h_b), hex::encode(h_cd),],
                proof
                    .iter()
                    .map(|e| hex::encode(e))
                    .collect::<Vec<String>>()
            );
        }
        {
            let root = tree.get_root();
            assert_eq!(hex::encode(h_abcd), hex::encode(root));
        }
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
