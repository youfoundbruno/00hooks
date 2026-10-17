//! MinHash signatures (PLAN §6a): 64 minimums of seeded 32-bit hashes over an item's word
//! 5-grams. Two signatures agree in about the share of slots that the Jaccard similarity of their
//! shingle sets says, so near-identical items are found without keeping their text.
//!
//! Each shingle is hashed once with MurmurHash3 (x86, 32-bit, seed 0) over its UTF-8, and slot `i`
//! takes `fmix32(base ^ seed_i)`, with `seed_i = fmix32(0x9e3779b9 * (i + 1))`. The relay computes
//! the same (`relay/src/screen.ts`); `fixtures/screen.v1.json` pins both.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::text;

/// Slots in a signature.
pub const SLOTS: usize = 64;
/// The default similarity at or above which two items count as the same (PLAN §6a).
pub const DEFAULT_THRESHOLD: f64 = 0.8;
/// A signature's text form: 256 bytes, unpadded base64url.
pub const ENCODED_LEN: usize = 342;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub [u32; SLOTS]);

pub fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// MurmurHash3, x86 32-bit.
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let (chunks, tail) = data.as_chunks::<4>();
    for c in chunks {
        let mut k = u32::from_le_bytes(*c);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let mut k = 0u32;
    for (i, b) in tail.iter().enumerate() {
        k |= u32::from(*b) << (8 * i);
    }
    if !tail.is_empty() {
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    fmix32(h)
}

fn seeds() -> [u32; SLOTS] {
    let mut s = [0u32; SLOTS];
    for (i, v) in s.iter_mut().enumerate() {
        *v = fmix32(0x9e37_79b9u32.wrapping_mul(i as u32 + 1));
    }
    s
}

impl Signature {
    /// The signature of a set of shingles; `None` for an empty set (nothing to compare).
    pub fn of_shingles(shingles: &[String]) -> Option<Signature> {
        if shingles.is_empty() {
            return None;
        }
        let seeds = seeds();
        let mut mins = [u32::MAX; SLOTS];
        for sh in shingles {
            let base = murmur3_32(sh.as_bytes(), 0);
            for (m, seed) in mins.iter_mut().zip(seeds.iter()) {
                let h = fmix32(base ^ seed);
                if h < *m {
                    *m = h;
                }
            }
        }
        Some(Signature(mins))
    }

    /// The signature of a text: its words, its 5-grams.
    pub fn of_text(s: &str) -> Option<Signature> {
        Self::of_shingles(&text::shingles(&text::tokens(s)))
    }

    /// The estimated Jaccard similarity: the share of slots that agree.
    pub fn similarity(&self, other: &Signature) -> f64 {
        let same = self
            .0
            .iter()
            .zip(other.0.iter())
            .filter(|(a, b)| a == b)
            .count();
        same as f64 / SLOTS as f64
    }

    /// Unpadded base64url of the slots, each big-endian.
    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(SLOTS * 4);
        for v in self.0 {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(s: &str) -> Option<Signature> {
        if s.len() != ENCODED_LEN {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
        if bytes.len() != SLOTS * 4 {
            return None;
        }
        let mut out = [0u32; SLOTS];
        for (i, c) in bytes.as_chunks::<4>().0.iter().enumerate() {
            out[i] = u32::from_be_bytes(*c);
        }
        Some(Signature(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur_matches_the_reference() {
        // Published MurmurHash3_x86_32 values.
        assert_eq!(murmur3_32(b"", 0), 0);
        assert_eq!(murmur3_32(b"", 1), 0x514e_28b7);
        assert_eq!(murmur3_32(b"hello", 0), 0x248b_fa47);
        assert_eq!(
            murmur3_32(b"The quick brown fox jumps over the lazy dog", 0),
            0x2e4f_f723
        );
    }

    #[test]
    fn near_identical_texts_are_similar_and_different_ones_are_not() {
        let base = "Congratulations! You have won a free crypto wallet worth 5000 dollars. Click the link below to claim your prize before midnight, only for today, do not miss out on this opportunity.";
        let a = Signature::of_text(base).unwrap();
        let b = Signature::of_text(&base.replace("5000", "7000")).unwrap();
        let c = Signature::of_text("Your order 1234 has shipped and will arrive on Tuesday between nine and noon. Thank you for shopping with us, we hope you enjoy the new kettle.").unwrap();
        assert_eq!(a.similarity(&a), 1.0);
        assert!(a.similarity(&b) >= 0.7, "{}", a.similarity(&b));
        assert!(a.similarity(&c) < 0.2, "{}", a.similarity(&c));
        assert_eq!(Signature::decode(&a.encode()), Some(a.clone()));
        assert_eq!(a.encode().len(), ENCODED_LEN);
        assert!(Signature::decode("short").is_none());
        assert!(Signature::of_text("  ...  ").is_none());
    }
}
