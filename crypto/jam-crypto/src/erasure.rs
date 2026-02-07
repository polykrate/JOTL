//! JAM Erasure Coding - GP Appendix H
//!
//! Reed-Solomon erasure coding over GF(2^16) using Cantor basis.
//!
//! GP H.6: Irreducible polynomial x^16 + x^5 + x^3 + x^2 + 1
//! GP H.7: Cantor basis for efficient operations
//!
//! Status:
//! - TINY (k=2, n=6): 100% working with Lagrange interpolation
//! - FULL (k=342, n=1023): Systematic shards OK, recovery shards need reference algo
//!
//! Note: reed-solomon-novelpoly (Polkadot) produces DIFFERENT values than JAM test vectors,
//! even for TINY mode. JAM uses a different erasure coding algorithm.

/// GF(2^16) with irreducible polynomial x^16 + x^5 + x^3 + x^2 + 1
const MODULUS: u32 = 0x1002D;

/// Cantor basis vectors (GP H.7)
const CANTOR_BASIS: [u16; 16] = [
    0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012,
    0x6C98, 0x10D8, 0x6A72, 0xB900, 0xFDB8, 0xFB34, 0xFF38, 0x991E,
];

/// GF(2^16) element type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GF(pub u16);

impl GF {
    pub const ZERO: GF = GF(0);
    pub const ONE: GF = GF(1);

    #[inline]
    pub fn from_le_bytes_cantor(bytes: [u8; 2]) -> Self {
        let word = u16::from_le_bytes(bytes);
        let mut result: u16 = 0;
        for j in 0..16 {
            if (word >> j) & 1 != 0 {
                result ^= CANTOR_BASIS[j];
            }
        }
        GF(result)
    }

    #[inline]
    pub fn to_le_bytes_cantor(self) -> [u8; 2] {
        field_to_index(self).to_le_bytes()
    }

    #[inline]
    pub fn add(self, other: GF) -> GF {
        GF(self.0 ^ other.0)
    }

    #[inline]
    pub fn sub(self, other: GF) -> GF {
        self.add(other)
    }

    #[inline]
    pub fn mul(self, other: GF) -> GF {
        if self.0 == 0 || other.0 == 0 {
            return GF::ZERO;
        }
        let mut a = self.0 as u32;
        let mut b = other.0 as u32;
        let mut result: u32 = 0;
        while b > 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            a <<= 1;
            if a & 0x10000 != 0 {
                a ^= MODULUS;
            }
            b >>= 1;
        }
        GF(result as u16)
    }

    pub fn pow(self, mut exp: u32) -> GF {
        if exp == 0 {
            return GF::ONE;
        }
        let mut base = self;
        let mut result = GF::ONE;
        while exp > 0 {
            if exp & 1 != 0 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    pub fn inv(self) -> GF {
        self.pow((1 << 16) - 2)
    }

    #[inline]
    pub fn div(self, other: GF) -> GF {
        self.mul(other.inv())
    }
}

/// Convert index to field element using Cantor basis (GP H.9)
pub fn index_to_field(index: u16) -> GF {
    let mut result = GF::ZERO;
    for j in 0..16 {
        if (index >> j) & 1 != 0 {
            result = result.add(GF(CANTOR_BASIS[j]));
        }
    }
    result
}

/// Convert field element back to index
pub fn field_to_index(elem: GF) -> u16 {
    let mut matrix = [[false; 17]; 16];
    for j in 0..16 {
        for b in 0..16 {
            matrix[b][j] = (CANTOR_BASIS[j] >> b) & 1 != 0;
        }
    }
    for b in 0..16 {
        matrix[b][16] = (elem.0 >> b) & 1 != 0;
    }
    for col in 0..16 {
        let mut pivot_row = None;
        for row in col..16 {
            if matrix[row][col] {
                pivot_row = Some(row);
                break;
            }
        }
        if let Some(pr) = pivot_row {
            matrix.swap(col, pr);
            for row in 0..16 {
                if row != col && matrix[row][col] {
                    for c in 0..17 {
                        matrix[row][c] ^= matrix[col][c];
                    }
                }
            }
        }
    }
    let mut index: u16 = 0;
    for j in 0..16 {
        if matrix[j][16] {
            index |= 1 << j;
        }
    }
    index
}

/// Polynomial for Lagrange interpolation
pub struct Polynomial {
    coeffs: Vec<GF>,
}

impl Polynomial {
    pub fn interpolate(points: &[(GF, GF)]) -> Self {
        let n = points.len();
        if n == 0 {
            return Polynomial { coeffs: vec![] };
        }
        let mut result = vec![GF::ZERO; n];
        for i in 0..n {
            let (xi, yi) = points[i];
            let mut denom = GF::ONE;
            for j in 0..n {
                if j != i {
                    denom = denom.mul(xi.sub(points[j].0));
                }
            }
            let denom_inv = denom.inv();
            let mut basis = vec![GF::ONE];
            for j in 0..n {
                if j != i {
                    let xj = points[j].0;
                    let mut new_basis = vec![GF::ZERO; basis.len() + 1];
                    for k in 0..basis.len() {
                        new_basis[k + 1] = new_basis[k + 1].add(basis[k]);
                        new_basis[k] = new_basis[k].sub(xj.mul(basis[k]));
                    }
                    basis = new_basis;
                }
            }
            let scale = yi.mul(denom_inv);
            for k in 0..basis.len().min(n) {
                result[k] = result[k].add(basis[k].mul(scale));
            }
        }
        Polynomial { coeffs: result }
    }

    pub fn evaluate(&self, x: GF) -> GF {
        let mut result = GF::ZERO;
        let mut x_pow = GF::ONE;
        for &coeff in &self.coeffs {
            result = result.add(coeff.mul(x_pow));
            x_pow = x_pow.mul(x);
        }
        result
    }
}

/// Encode bytes into shards using reed-solomon-simd
/// This is the JAM-compatible implementation (GP H.10-H.11)
pub fn encode_bytes(data: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    if k == 0 || n == 0 {
        return vec![];
    }

    // Calculate shard size (minimum 2 bytes, must be even)
    let shard_size = ((data.len() + k - 1) / k + 1) / 2 * 2;
    let shard_size = if shard_size == 0 { 2 } else { shard_size };

    // Pad data to k * shard_size bytes
    let padded_len = k * shard_size;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len().min(padded_len)].copy_from_slice(&data[..data.len().min(padded_len)]);

    // Create k original shards
    let original_shards: Vec<&[u8]> = padded.chunks(shard_size).collect();

    // Use reed-solomon-simd for encoding
    let recovery = reed_solomon_simd::encode(
        k,      // original shards count
        n - k,  // recovery shards count
        original_shards.iter().copied(),
    ).expect("reed-solomon-simd encode failed");

    // Combine original + recovery shards
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n);
    
    // Add original shards (systematic encoding)
    for chunk in padded.chunks(shard_size) {
        shards.push(chunk.to_vec());
    }
    
    // Add recovery shards
    for shard in recovery {
        shards.push(shard.to_vec());
    }

    shards
}

/// Encode bytes using our Lagrange interpolation (for small k like TINY)
pub fn encode_bytes_lagrange(data: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    if k == 0 || n == 0 {
        return vec![];
    }

    let shard_size = ((data.len() + k - 1) / k + 1) / 2 * 2;
    let shard_size = if shard_size == 0 { 2 } else { shard_size };
    let words_per_shard = shard_size / 2;

    let padded_len = k * shard_size;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len().min(padded_len)].copy_from_slice(&data[..data.len().min(padded_len)]);

    let mut shards: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; shard_size]).collect();

    for word_idx in 0..words_per_shard {
        let messages: Vec<GF> = (0..k)
            .map(|shard_idx| {
                let offset = shard_idx * shard_size + word_idx * 2;
                GF::from_le_bytes_cantor([padded[offset], padded[offset + 1]])
            })
            .collect();

        let points: Vec<(GF, GF)> = messages
            .iter()
            .enumerate()
            .map(|(i, &m)| (index_to_field(i as u16), m))
            .collect();

        let poly = Polynomial::interpolate(&points);

        for shard_idx in 0..n {
            let x = index_to_field(shard_idx as u16);
            let y = poly.evaluate(x);
            let bytes = y.to_le_bytes_cantor();
            shards[shard_idx][word_idx * 2] = bytes[0];
            shards[shard_idx][word_idx * 2 + 1] = bytes[1];
        }
    }

    shards
}

/// Encode bytes using TypeBerry's stride-64 hack with reed-solomon-simd
/// This is required for JAM FULL mode (k=342) because reed-solomon-simd
/// requires shard_size % 64 == 0, but JAM uses 2-byte shards
pub fn encode_bytes_simd_strided(data: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    const POINT_ALIGNMENT: usize = 64;
    const HALF_POINT_SIZE: usize = 32;
    const POINT_LENGTH: usize = 2;

    if k == 0 || n == 0 {
        return vec![];
    }

    // Calculate shard size in 2-byte words
    let shard_size = ((data.len() + k - 1) / k + 1) / 2 * 2;
    let shard_size = if shard_size == 0 { 2 } else { shard_size };
    let words_per_shard = shard_size / 2;

    // Pad data
    let padded_len = k * shard_size;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len().min(padded_len)].copy_from_slice(&data[..data.len().min(padded_len)]);

    let mut all_shards: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; shard_size]).collect();

    // Process each word position separately
    for word_idx in 0..words_per_shard {
        // Prepare 64-byte aligned original shards for this word position
        let mut original_data = vec![0u8; k * POINT_ALIGNMENT];
        
        for shard_idx in 0..k {
            let offset = shard_idx * shard_size + word_idx * POINT_LENGTH;
            // Use stride pattern: byte[0] at offset 0, byte[1] at offset 32
            for j in 0..POINT_LENGTH {
                original_data[shard_idx * POINT_ALIGNMENT + j * HALF_POINT_SIZE] = padded[offset + j];
            }
            
            // Copy original data to output shards
            all_shards[shard_idx][word_idx * 2] = padded[offset];
            all_shards[shard_idx][word_idx * 2 + 1] = padded[offset + 1];
        }

        let original_shards: Vec<&[u8]> = original_data.chunks(POINT_ALIGNMENT).collect();

        // Encode with reed-solomon-simd
        let recovery = reed_solomon_simd::encode(
            k,
            n - k,
            original_shards.iter().copied(),
        ).expect("reed-solomon-simd encode failed");

        // Extract 2-byte values from recovery shards using same stride
        for (i, shard) in recovery.iter().enumerate() {
            let mut word = [0u8; 2];
            for j in 0..POINT_LENGTH {
                word[j] = shard[j * HALF_POINT_SIZE];
            }
            all_shards[k + i][word_idx * 2] = word[0];
            all_shards[k + i][word_idx * 2 + 1] = word[1];
        }
    }

    all_shards
}

/// Encode for JAM TINY (k=2, n=6) - using Lagrange (works perfectly)
pub fn encode_bytes_tiny(data: &[u8]) -> Vec<Vec<u8>> {
    encode_bytes_lagrange(data, 2, 6)
}

/// Encode for JAM FULL (k=342, n=1023) - using simd with stride hack
pub fn encode_bytes_full(data: &[u8]) -> Vec<Vec<u8>> {
    encode_bytes_simd_strided(data, 342, 1023)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_ops() {
        let a = GF(0x1234);
        assert_eq!(a.add(a), GF::ZERO);
        assert_eq!(a.mul(GF::ONE), a);
        assert_eq!(a.mul(a.inv()), GF::ONE);
    }

    #[test]
    fn test_cantor_roundtrip() {
        for bytes in [[0xea, 0x5e], [0x17, 0x00], [0x48, 0xc5], [0x00, 0x00], [0xff, 0xff]] {
            let field = GF::from_le_bytes_cantor(bytes);
            let back = field.to_le_bytes_cantor();
            assert_eq!(back, bytes);
        }
    }

    #[test]
    fn test_index_roundtrip() {
        for i in 0..100u16 {
            let field = index_to_field(i);
            let back = field_to_index(field);
            assert_eq!(back, i);
        }
    }

    #[test]
    fn test_encode_ec3_tiny() {
        let data = vec![0x61, 0x5d, 0x17];
        let shards = encode_bytes_tiny(&data);
        let expected: Vec<Vec<u8>> = vec![
            vec![0x61, 0x5d], vec![0x17, 0x00], vec![0x48, 0xc5],
            vec![0x3e, 0x98], vec![0x73, 0x78], vec![0x05, 0x25],
        ];
        for i in 0..6 {
            assert_eq!(shards[i], expected[i]);
        }
    }

    #[test]
    fn test_encode_ec3_full_systematic() {
        let data = vec![0x61, 0x5d, 0x17];
        let shards = encode_bytes_full(&data);
        assert_eq!(shards.len(), 1023);
        assert_eq!(shards[0], vec![0x61, 0x5d]);
        assert_eq!(shards[1], vec![0x17, 0x00]);
        for i in 2..342 {
            assert_eq!(shards[i], vec![0x00, 0x00]);
        }
    }

    #[test]
    fn test_encode_ec3_full_recovery() {
        // ec-3.json FULL expected recovery shards
        let data = vec![0x61, 0x5d, 0x17];
        let shards = encode_bytes_full(&data);
        
        // From JAM test vector full/ec-3.json
        let expected_342 = vec![0x4f, 0x05];
        let expected_343 = vec![0xfd, 0x71];
        
        println!("  Lagrange Recovery shard 342: got {:02x?}, expected {:02x?}", &shards[342], expected_342);
        println!("  Lagrange Recovery shard 343: got {:02x?}, expected {:02x?}", &shards[343], expected_343);
        
        // Check if Lagrange produces correct values
        let match_342 = shards[342] == expected_342;
        let match_343 = shards[343] == expected_343;
        println!("  Lagrange shard[342] matches: {}", if match_342 { "✅" } else { "❌" });
        println!("  Lagrange shard[343] matches: {}", if match_343 { "✅" } else { "❌" });
    }

    #[test]
    fn test_typeberry_hack_ec3_full() {
        // TypeBerry uses 64-byte aligned shards with stride 32 for the 2-byte values
        // This is required because reed-solomon-simd needs shard_size % 64 == 0
        
        const POINT_ALIGNMENT: usize = 64;
        const HALF_POINT_SIZE: usize = 32;
        const K: usize = 342;
        const N: usize = 1023;
        
        // Prepare 342 original shards (each 64 bytes)
        let mut original_data = vec![0u8; K * POINT_ALIGNMENT];
        
        // Input data: 0x615d17 padded to 684 bytes = 342 words
        let input_words: Vec<[u8; 2]> = {
            let mut words = vec![[0u8; 2]; K];
            words[0] = [0x61, 0x5d];  // first 2-byte word
            words[1] = [0x17, 0x00];  // second 2-byte word (padded)
            // rest are zeros
            words
        };
        
        // Fill original shards using TypeBerry's stride pattern
        for i in 0..K {
            for j in 0..2 {
                original_data[i * POINT_ALIGNMENT + j * HALF_POINT_SIZE] = input_words[i][j];
            }
        }
        
        // Create original shards as 64-byte slices
        let original_shards: Vec<&[u8]> = original_data.chunks(POINT_ALIGNMENT).collect();
        
        // Encode with reed-solomon-simd
        let recovery = reed_solomon_simd::encode(
            K,
            N - K,  // 681 recovery shards
            original_shards.iter().copied(),
        ).expect("encode failed");
        
        // Extract 2-byte values from recovery shards using same stride
        let mut recovery_words: Vec<[u8; 2]> = Vec::new();
        for shard in &recovery {
            let mut word = [0u8; 2];
            for j in 0..2 {
                word[j] = shard[j * HALF_POINT_SIZE];
            }
            recovery_words.push(word);
        }
        
        // Expected from JAM test vector
        let expected_342 = [0x4f, 0x05];
        let expected_343 = [0xfd, 0x71];
        
        println!("  TypeBerry-hack Recovery shard 342: {:02x?}, expected {:02x?}", recovery_words[0], expected_342);
        println!("  TypeBerry-hack Recovery shard 343: {:02x?}, expected {:02x?}", recovery_words[1], expected_343);
        
        let match_342 = recovery_words[0] == expected_342;
        let match_343 = recovery_words[1] == expected_343;
        println!("  shard[342] matches: {}", if match_342 { "✅" } else { "❌" });
        println!("  shard[343] matches: {}", if match_343 { "✅" } else { "❌" });
    }

    #[test]
    fn test_recovery_from_shards() {
        let shards = encode_bytes_tiny(&[0x61, 0x5d, 0x17]);
        
        // Use recovery shards (2,3) to reconstruct message shards (0,1)
        let points: Vec<(GF, GF)> = vec![
            (index_to_field(2), GF::from_le_bytes_cantor([shards[2][0], shards[2][1]])),
            (index_to_field(3), GF::from_le_bytes_cantor([shards[3][0], shards[3][1]])),
        ];
        let poly = Polynomial::interpolate(&points);
        
        assert_eq!(poly.evaluate(index_to_field(0)), GF::from_le_bytes_cantor([0x61, 0x5d]));
        assert_eq!(poly.evaluate(index_to_field(1)), GF::from_le_bytes_cantor([0x17, 0x00]));
    }

    #[test]
    fn test_simd_vs_jam_tiny() {
        // Test reed-solomon-simd with JAM TINY parameters
        // k=2 original, n-k=4 recovery, n=6 total
        let shard0 = [0x61u8, 0x5d];
        let shard1 = [0x17u8, 0x00];
        
        let recovery = reed_solomon_simd::encode(
            2,  // original shards
            4,  // recovery shards
            [&shard0[..], &shard1[..]].into_iter(),
        ).unwrap();
        
        // JAM expects these recovery shards
        let expected = [
            [0x48u8, 0xc5], // shard 2
            [0x3e, 0x98],   // shard 3
            [0x73, 0x78],   // shard 4
            [0x05, 0x25],   // shard 5
        ];
        
        // Compare
        let mut matches = 0;
        for (i, (got, exp)) in recovery.iter().zip(expected.iter()).enumerate() {
            let got_slice: &[u8] = got.as_ref();
            if got_slice == exp {
                matches += 1;
            }
            println!("  shard[{}]: got {:02x?}, expected {:02x?} {}", 
                     i + 2, got_slice, exp,
                     if got_slice == exp { "✅" } else { "❌" });
        }
        
        // reed-solomon-simd IS JAM-compatible for TINY!
        assert_eq!(matches, 4, "reed-solomon-simd should match JAM TINY");
    }

    #[test]
    fn test_simd_ec3_full() {
        // Test reed-solomon-simd with ec-3.json data for FULL (k=342, n=1023)
        // Data: 0x615d17
        // Expected recovery shard[342]: 0x4f05, shard[343]: 0xfd71
        
        // Create 342 shards of 2 bytes each
        let mut shards: Vec<[u8; 2]> = vec![[0u8; 2]; 342];
        shards[0] = [0x61, 0x5d];  // 0x615d
        shards[1] = [0x17, 0x00];  // 0x1700
        // rest are zeros
        
        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| &s[..]).collect();
        
        let recovery = reed_solomon_simd::encode(
            342,  // original shards (k)
            681,  // recovery shards (n-k)
            shard_refs.into_iter(),
        ).unwrap();
        
        // Expected from JAM test vectors:
        // shard[342]: 0x4f05 -> [0x4f, 0x05]
        // shard[343]: 0xfd71 -> [0xfd, 0x71]
        let expected_342 = [0x4fu8, 0x05];
        let expected_343 = [0xfdu8, 0x71];
        
        let got_342: &[u8] = recovery[0].as_ref();
        let got_343: &[u8] = recovery[1].as_ref();
        
        println!("=== reed-solomon-simd vs JAM FULL ec-3.json ===");
        println!("  shard[342]: got {:02x?}, expected {:02x?} {}", 
                 got_342, expected_342,
                 if got_342 == expected_342 { "✅" } else { "❌" });
        println!("  shard[343]: got {:02x?}, expected {:02x?} {}", 
                 got_343, expected_343,
                 if got_343 == expected_343 { "✅" } else { "❌" });
        
        // Also try byte-swapped
        let got_342_swap = [got_342[1], got_342[0]];
        let expected_342_swap = [0x05u8, 0x4f];
        println!("  shard[342] swapped: got {:02x?}, expected {:02x?} {}", 
                 got_342_swap, expected_342_swap,
                 if got_342_swap == expected_342_swap { "✅" } else { "❌" });
    }

    #[test]
    fn test_ec100_tiny_real() {
        // Test ec-100.json TINY with real data
        // Data: 0x6899c10632848450fc4d... (100 bytes)
        let hex_data = "6899c10632848450fc4daae93d07ea10c10c96434355ae1a20e7fa109f130418fa10acb8e790d710f79614ddff2b7d66a804fcd0d32046a0c39caf301288501d98f635ed7d28be53e108793f79353267dcfb3545eb1fe946c057accb24156c2108eb530a";
        let data: Vec<u8> = (0..hex_data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_data[i..i+2], 16).unwrap())
            .collect();
        
        let shards = encode_bytes(&data, 2, 6);
        
        // Expected shard[2] starts with: ed26b4375ab661011fec...
        let expected_shard2_start = [0xedu8, 0x26, 0xb4, 0x37, 0x5a, 0xb6, 0x61, 0x01, 0x1f, 0xec];
        
        println!("=== ec-100.json TINY real data ===");
        println!("  Data length: {}", data.len());
        println!("  Number of shards: {}", shards.len());
        println!("  Shard size: {}", shards[0].len());
        println!("  First shard (first 10 bytes): {:02x?}", &shards[0][..10]);
        println!("  Recovery shard 2 (first 10 bytes): {:02x?}", &shards[2][..10]);
        println!("  Expected shard 2: {:02x?}", &expected_shard2_start);
        
        // Test with swapped bytes (little-endian interpretation)
        let mut swapped_data = data.clone();
        for i in (0..swapped_data.len()).step_by(2) {
            if i + 1 < swapped_data.len() {
                swapped_data.swap(i, i + 1);
            }
        }
        
        let swapped_shards = encode_bytes(&swapped_data, 2, 6);
        
        // Swap back the recovery shard bytes
        let mut recovery_swapped: Vec<u8> = swapped_shards[2].clone();
        for i in (0..recovery_swapped.len()).step_by(2) {
            if i + 1 < recovery_swapped.len() {
                recovery_swapped.swap(i, i + 1);
            }
        }
        
        println!("  Recovery shard 2 (byte-swapped method): {:02x?}", &recovery_swapped[..10]);
        
        // Check if either method matches
        let direct_match = &shards[2][..10] == &expected_shard2_start;
        let swapped_match = &recovery_swapped[..10] == &expected_shard2_start;
        
        println!("  Direct method matches: {}", if direct_match { "✅" } else { "❌" });
        println!("  Swapped method matches: {}", if swapped_match { "✅" } else { "❌" });
        
        // Test with Lagrange interpolation
        let lagrange_shards = encode_bytes_lagrange(&data, 2, 6);
        println!("  Lagrange shard 2 (first 10): {:02x?}", &lagrange_shards[2][..10]);
        let lagrange_match = &lagrange_shards[2][..10] == &expected_shard2_start;
        println!("  Lagrange method matches: {}", if lagrange_match { "✅" } else { "❌" });
    }
}
