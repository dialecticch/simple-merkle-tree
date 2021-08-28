# Simple Merkle Tree implementation

To be used hand-in-hand with Solidity, that's why it's using `keccak256` for hashing!

Example usage

```rust
use simple_merkle_tree::MerkleTree;
let elements = (0..4)
    .map(|el| format!("item-string-{:}", el).into_bytes())
    .collect::<Vec<Vec<u8>>>();

let tree = MerkleTree::new(elements.clone());
let a = &elements[0];
let b = &elements[1];
let c = &elements[2];
let d = &elements[3];

let h_a = MerkleTree::hash(a); // Part of the proof
let h_b = MerkleTree::hash(b);
let h_c = MerkleTree::hash(c); // Part of the proof
let h_d = MerkleTree::hash(d); // Part of the proof
let h_ab = MerkleTree::combined_hash(&h_a, &h_b); // Part of the proof
let h_cd = MerkleTree::combined_hash(&h_c, &h_d);
let h_abcd = MerkleTree::combined_hash(&h_ab, &h_cd);

let proof = tree.get_proof(d).unwrap();
assert_eq!(proof.len(), 2);

assert_eq!(
    vec![hex::encode(h_c), hex::encode(h_ab),],
    proof
        .iter()
        .map(|e| hex::encode(e))
        .collect::<Vec<String>>()
);

let root = tree.get_root();
assert_eq!(hex::encode(h_abcd), hex::encode(root));
```
