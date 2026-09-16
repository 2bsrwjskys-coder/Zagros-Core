// Artımlı, yol sıkıştırmalı İKİLİ radix Merkle Patricia Trie (chain state kökü).
// Anahtar adresin keccak256'sı, değer serileşmiş hesabın keccak256'sı. Her
// `Branch` kendi dallanma bit indeksini tuttuğundan yapı KANONİKTİR (kök yalnız
// küme'ye bağlı, ekleme sırasından bağımsız) ve tek çocuklu dal O(1) sadeleşir.
// Yaprak güncellemesi yalnız kökten yaprağa O(log n) yolu yeniden hesaplar.

use sha3::{Digest, Keccak256};

/// Boş trie'nin kök hash'i, hiçbir yaprak/dal hash'iyle çakışmaz (leaf/branch
/// hash'leri domain-separator baytıyla üretilir, bu ise sabit sıfırdır).
const EMPTY_ROOT: [u8; 32] = [0u8; 32];

const KEY_BITS: usize = 256;

#[derive(Clone)]
enum Node {
    /// Tam anahtarı taşır; hash'i keccak(0x00 ‖ key ‖ value) ile anlık üretilir.
    Leaf { key: [u8; 32], value: [u8; 32] },
    /// `bit_index`: iki alt ağacın ayrıştığı bit. `prefix`: alt ağaçtaki
    /// herhangi bir anahtar (yalnızca [0..bit_index) bitleri anlamlı). `hash`:
    /// keccak(0x01 ‖ hash(left) ‖ hash(right)), inşa anında hesaplanıp saklanır.
    Branch {
        bit_index: u16,
        prefix: [u8; 32],
        hash: [u8; 32],
        left: Box<Node>,  // bit == 0
        right: Box<Node>, // bit == 1
    },
}

#[inline]
fn bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

/// İki anahtarın farklılaştığı İLK bit indeksi (0..256); eşitse 256.
fn first_diff_bit(a: &[u8; 32], b: &[u8; 32]) -> usize {
    for byte in 0..32 {
        if a[byte] != b[byte] {
            let x = a[byte] ^ b[byte];
            return byte * 8 + x.leading_zeros() as usize;
        }
    }
    KEY_BITS
}

fn leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update([0x00]); // domain separator: leaf
    hasher.update(key);
    hasher.update(value);
    hasher.finalize().into()
}

fn branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update([0x01]); // domain separator: branch
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn node_hash(node: &Node) -> [u8; 32] {
    match node {
        Node::Leaf { key, value } => leaf_hash(key, value),
        Node::Branch { hash, .. } => *hash,
    }
}

fn rep_key(node: &Node) -> [u8; 32] {
    match node {
        Node::Leaf { key, .. } => *key,
        Node::Branch { prefix, .. } => *prefix,
    }
}

/// `bit_index`'te ayrışan iki alt ağacı doğru sırayla (bit==0 sola) bir Branch'e
/// koyar. Hash inşa anında hesaplanır.
fn make_branch(bit_index: u16, a: Node, b: Node) -> Node {
    let (left, right) = if bit(&rep_key(&a), bit_index as usize) == 0 {
        (a, b)
    } else {
        (b, a)
    };
    let hash = branch_hash(&node_hash(&left), &node_hash(&right));
    // prefix: left ve right [0..bit_index) bitlerinde eşittir; birinden alınır.
    let prefix = rep_key(&left);
    Node::Branch {
        bit_index,
        prefix,
        hash,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn insert_node(node: Node, key: [u8; 32], value: [u8; 32]) -> Node {
    match node {
        Node::Leaf { key: k, value: v } => {
            if k == key {
                Node::Leaf { key, value }
            } else {
                let d = first_diff_bit(&k, &key) as u16;
                make_branch(
                    d,
                    Node::Leaf { key: k, value: v },
                    Node::Leaf { key, value },
                )
            }
        }
        Node::Branch {
            bit_index,
            prefix,
            left,
            right,
            ..
        } => {
            let d = first_diff_bit(&prefix, &key);
            if (d as u16) < bit_index {
                // Anahtar bu dalın ayrışma noktasından ÖNCE ayrılıyor: üstte
                // yeni bir dal oluştur (mevcut dalı bir alt ağaç olarak taşı).
                let existing = make_branch(bit_index, *left, *right);
                make_branch(d as u16, existing, Node::Leaf { key, value })
            } else if bit(&key, bit_index as usize) == 0 {
                let new_left = insert_node(*left, key, value);
                make_branch(bit_index, new_left, *right)
            } else {
                let new_right = insert_node(*right, key, value);
                make_branch(bit_index, *left, new_right)
            }
        }
    }
}

fn remove_node(node: Node, key: &[u8; 32]) -> Option<Node> {
    match node {
        Node::Leaf { key: k, value } => {
            if &k == key {
                None
            } else {
                Some(Node::Leaf { key: k, value })
            }
        }
        Node::Branch {
            bit_index,
            prefix,
            left,
            right,
            ..
        } => {
            let d = first_diff_bit(&prefix, key);
            if (d as u16) < bit_index {
                // Anahtar bu alt ağaçta yok, dalı olduğu gibi yeniden kur.
                return Some(make_branch(bit_index, *left, *right));
            }
            if bit(key, bit_index as usize) == 0 {
                match remove_node(*left, key) {
                    // Sol çocuk yok oldu: sağ çocuğu DOĞRUDAN yukarı çek
                    // (kendi bit-indexini taşıdığından kanonik kalır).
                    None => Some(*right),
                    Some(new_left) => Some(make_branch(bit_index, new_left, *right)),
                }
            } else {
                match remove_node(*right, key) {
                    None => Some(*left),
                    Some(new_right) => Some(make_branch(bit_index, *left, new_right)),
                }
            }
        }
    }
}

/// Artırımlı Merkle Patricia Trie. `insert`/`remove` yalnızca ilgili kök-yaprak
/// yolunu O(log n)'de günceller; `root_hash` O(1)'dir (kök düğümün saklı
/// hash'ini döner).
#[derive(Clone, Default)]
pub struct MerkleTrie {
    root: Option<Node>,
}

impl MerkleTrie {
    pub fn new() -> Self {
        Self { root: None }
    }

    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) {
        let root = self.root.take();
        self.root = Some(match root {
            None => Node::Leaf { key, value },
            Some(node) => insert_node(node, key, value),
        });
    }

    pub fn remove(&mut self, key: &[u8; 32]) {
        if let Some(node) = self.root.take() {
            self.root = remove_node(node, key);
        }
    }

    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            None => EMPTY_ROOT,
            Some(node) => node_hash(node),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Bir (anahtar,değer) kümesini sıfırdan bir trie'ye kurar, artırımlı
    /// sonucun bununla eşleşmesi determinizmi kanıtlar.
    fn build(pairs: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
        let mut t = MerkleTrie::new();
        for (key, value) in pairs {
            t.insert(*key, *value);
        }
        t.root_hash()
    }

    #[test]
    fn empty_trie_has_stable_empty_root() {
        assert_eq!(MerkleTrie::new().root_hash(), EMPTY_ROOT);
    }

    #[test]
    fn single_leaf_root_is_its_leaf_hash() {
        let mut t = MerkleTrie::new();
        t.insert(k(1), k(9));
        assert_eq!(t.root_hash(), leaf_hash(&k(1), &k(9)));
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        // Farklı sıralarla eklenen AYNI küme, AYNI kökü üretmeli (kanoniklik).
        let a = build(&[(k(1), k(10)), (k(2), k(20)), (k(3), k(30)), (k(200), k(40))]);
        let b = build(&[(k(200), k(40)), (k(1), k(10)), (k(3), k(30)), (k(2), k(20))]);
        let c = build(&[(k(3), k(30)), (k(200), k(40)), (k(2), k(20)), (k(1), k(10))]);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn updating_a_value_changes_the_root_deterministically() {
        let before = build(&[(k(1), k(10)), (k(2), k(20))]);
        let after = build(&[(k(1), k(11)), (k(2), k(20))]);
        assert_ne!(before, after);
        // Aynı son duruma farklı yoldan varmak aynı kökü verir.
        let mut t = MerkleTrie::new();
        t.insert(k(1), k(10));
        t.insert(k(2), k(20));
        t.insert(k(1), k(11)); // güncelle
        assert_eq!(t.root_hash(), after);
    }

    #[test]
    fn remove_yields_the_same_root_as_rebuilding_without_the_key() {
        let mut t = MerkleTrie::new();
        for i in 1..=20u8 {
            t.insert(k(i), k(i.wrapping_mul(3)));
        }
        // 5, 12, 17'yi sil.
        for i in [5u8, 12, 17] {
            t.remove(&k(i));
        }
        let expected: Vec<_> = (1..=20u8)
            .filter(|i| ![5u8, 12, 17].contains(i))
            .map(|i| (k(i), k(i.wrapping_mul(3))))
            .collect();
        assert_eq!(t.root_hash(), build(&expected));
    }

    #[test]
    fn remove_all_returns_to_empty_root() {
        let mut t = MerkleTrie::new();
        for i in 1..=10u8 {
            t.insert(k(i), k(i));
        }
        for i in 1..=10u8 {
            t.remove(&k(i));
        }
        assert_eq!(t.root_hash(), EMPTY_ROOT);
    }

    #[test]
    fn incremental_matches_rebuild_across_mixed_ops() {
        // Karışık ekleme/güncelleme/silme dizisi, her adımda sıfırdan-inşa ile
        // aynı kökü vermeli. Deterministik "rastgele": basit bir LCG.
        let mut t = MerkleTrie::new();
        let mut model: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
            std::collections::BTreeMap::new();
        let mut seed: u64 = 0x1234_5678;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 24) as u8
        };
        for _ in 0..500 {
            let key_byte = next();
            let mut key = [0u8; 32];
            key[0] = key_byte;
            key[1] = next();
            if next() % 4 == 0 {
                t.remove(&key);
                model.remove(&key);
            } else {
                let val = k(next());
                t.insert(key, val);
                model.insert(key, val);
            }
            let expected: Vec<_> = model.iter().map(|(kk, vv)| (*kk, *vv)).collect();
            assert_eq!(t.root_hash(), build(&expected));
        }
    }
}
