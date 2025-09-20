use ark_bls12_381::{g1::Config as G1Config, Fr, G1Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
    HashToCurve, // Trait providing .hash() method for hashing to curve points
};
use ark_ec::PrimeGroup; // Trait for elliptic curve group operations
use ark_ff::field_hashers::DefaultFieldHasher; // Field hasher for hash-to-curve
use ark_ff::{PrimeField, UniformRand}; // Traits for finite field operations and random generation
use sha2::Sha256;

// Hash-to-curve implementation for BLS12-381 G1 group
// It needs:
// - G1Projective: The target curve group (G1)
// - DefaultFieldHasher<Sha256, 128>: Field hasher (SHA-256)
// - WBMap<G1Config>: Wahby-Boneh mapping algorithm (don't try to understand it)
type H2C = MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>;

// Derive the second generator H for Pedersen commitments using hash-to-curve
//
// input:
// - dst: Domain Separation Tag - ensures this hash-to-curve operation is
//        cryptographically separated from other uses of the same curve
//
// out: A G1Projective point
pub fn derive_h(dst: &'static [u8]) -> G1Projective {
    // In production, this could be a more descriptive protocol identifier
    let msg = b"PEDERSEN_COMMITMENT_H_GENERATOR";
    let hasher = <H2C as HashToCurve<_>>::new(dst).expect("Failed to initialize hash-to-curve");
    hasher.hash(msg).expect("Hash-to-curve failed").into()
}

// Generate a Pedersen commitment
//
// A Pedersen commitment is computed as: C = m*G + r*H.
// input:
// - m: the message/value being committed to
// - r: random factor (ensures hiding property)
// - G: generator of the elliptic curve group
// - H: other generator, independent from G
//
// output:
// - g: The first generator (G)
// - h: The second generator (H)
// - r: Random blinding factor (scalar in Fp)
// - m: Message/value to commit to (scalar in Fp)
//
// Returns: G1 element (G and H are from G1)
fn commitment_generation(g: G1Projective, h: G1Projective, r: Fr, m: Fr) -> G1Projective {
    // Compute m*G + r*H using scalar multiplication and group addition
    // mul_bigint performs scalar multiplication: scalar * group_element
    g.mul_bigint(m.into_bigint()) + h.mul_bigint(r.into_bigint())
}

// Generate a random scalar for commitment
fn random_r() -> Fr {
    // Note: We use ark_std's test_rng for compatibility with arkworks ecosystem
    let mut rng = ark_std::test_rng();
    Fr::rand(&mut rng)
}

fn main() {
    /*
    Hash-to-Curve Explanation

        1. Hash-to-curve maps arbitrary byte strings to curve points
        2. The DST ensures domain separation from other applications
        3. This provides cryptographically secure independence between G and H
        4. Unlike random scalar multiplication, this is deterministic and verifiable

    */

    // Using generator of an abelian group (additive group).
    let generator = G1Projective::generator();

    // Define a fixed Domain Separation Tag (DST)
    // The DST ensures that our hash-to-curve is domain-separated from other uses
    // This prevents attacks where the same input might be used in different contexts
    const DST: &[u8] = b"PEDERSEN:BLS12-381";

    // Generate H that is cryptographically independent from G using hash-to-curve
    // This method hashes a fixed message with our Domain Separation Tag (DST)
    let h = derive_h(DST);

    // Generate a random blinding factor r
    // This must be kept secret to maintain the hiding property
    let r = random_r();

    // The message we want to commit to
    let m = Fr::from(2025);

    // Generate the Pedersen commitment: C = m*G + r*H
    let commitment = commitment_generation(generator, h, r, m);

    // Security verification: Ensure H is different from G
    // This should always be true with proper hash-to-curve implementation
    // If H == G, the commitment scheme would be insecure
    assert_ne!(generator, h, "H must be different from G for security");

    // Display the results
    println!("--> Pedersen Commitment");
    println!("Standard Generator G: {}", generator);
    println!("Hash-derived Generator H: {}", h);
    println!("Message m: {}", m);
    println!("Blinding factor r: {}", r);
    println!("Commitment C = m*G + r*H: {}", commitment);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homomorphism() {
        let mut rng = ark_std::test_rng();

        const MAGIC_STRING: &[u8] = b"hashed string 1";
        let generator_1_test = G1Projective::rand(&mut rng);
        let h_1_test = derive_h(MAGIC_STRING);

        let r_1_test = random_r();
        let r_2_test = random_r();

        let m_1_test = Fr::from(2025);
        let m_2_test = Fr::from(1961);

        let commit_1 = commitment_generation(generator_1_test.clone(), h_1_test.clone(), r_1_test.clone(), m_1_test.clone()); 
        let commit_2 = commitment_generation(generator_1_test.clone(), h_1_test.clone(), r_2_test.clone(), m_2_test.clone());
        let commit_combined = commitment_generation(generator_1_test, h_1_test, r_2_test + r_1_test, m_2_test + m_1_test);

        assert_eq!(commit_combined, commit_1 + commit_2);
    }
}
