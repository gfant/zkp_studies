use ark_bls12_381::{g1::Config as G1Config, Fr, G1Affine, G1Projective}; // Has to be G1Affine, not G1Projective
use ark_ec::hashing::{
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
    HashToCurve, // Trait providing .hash() method for hashing to curve points
};
use ark_ec::PrimeGroup; // Traits for operations in groups related to curves
use ark_ff::field_hashers::DefaultFieldHasher; // Field hasher for hash-to-curve.
use ark_ff::{PrimeField, UniformRand}; // For prime field operations and random generation
use sha2::Sha256;

/* Relevant lessons learned here:
 *
 *   - Projective values are better for math (additions, scalar mul, MSM)
 *   - Affine values are better for protocol edges (serialization, hashing, comparisons)
 *   - Keep computations in projective; only convert to affine when needed (protocols).
 *   - Affine to Projective is cheap, but Projective to Affine is expensive.
 */

// Hash-to-curve implementation for BLS12-381 G1 group
// It needs:
// - G1Projective: The target curve group (G1)
// - WBMap<G1Config>: Wahby-Boneh mapping algorithm (don't try to understand it)
// - DefaultFieldHasher<Sha256, 128>: Field hasher (SHA-256)
type H2C = MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256>, WBMap<G1Config>>;

// Derive the second generator H for Pedersen commitments using hash-to-curve.
// The output is a G1Projective element
pub fn derive_h(dst: &'static [u8]) -> G1Projective {
    // In production, this could be a more descriptive protocol identifier
    let msg = b"PEDERSEN_COMMITMENT_H_GENERATOR";
    let hasher = <H2C as HashToCurve<_>>::new(dst).expect("failed to init hash-to-curve");
    let h_affine: G1Affine = hasher.hash(msg).expect("hash-to-curve failed");
    h_affine.into() // G1Affine -> G1Projective
}

// Generate a Pedersen commitment
// A Pedersen commitment is computed as: C = m*G + r*H.
// Using projective elements for better math
fn commitment_generation(g: G1Projective, h: G1Projective, r: Fr, m: Fr) -> G1Projective {
    // Compute m*G + r*H using scalar multiplication and group addition
    // mul_bigint performs scalar multiplication: scalar * group_element
    g.mul_bigint(m.into_bigint()) + h.mul_bigint(r.into_bigint())
}

fn main() {
    // Using generator of an abelian group (additive group).
    let generator = G1Projective::generator();
    let mut rng = ark_std::test_rng();

    // Define a fixed Domain Separation Tag (DST)
    // The DST ensures that our hash-to-curve is domain-separated from other uses
    // This prevents attacks where the same input might be used in different contexts
    const DST: &[u8] = b"PEDERSEN:BLS12-381";

    // Generate H that is cryptographically independent from G using hash-to-curve
    // This method hashes a fixed message with our Domain Separation Tag (DST)
    let h = derive_h(DST);

    // Generate a random blinding factor r
    // This must be kept secret to maintain the hiding property
    let r = Fr::rand(&mut rng);

    // The message we want to commit to
    let m = Fr::from(2025);

    // Generate the Pedersen commitment: C = m*G + r*H
    let _commitment = commitment_generation(generator, h, r, m);

    // Security verification: Ensure H is different from G
    // This should always be true with proper hash-to-curve implementation
    // If H == G, the commitment scheme would be insecure
    assert_ne!(generator, h, "H must be different from G for security");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homomorphism() {
        let mut rng = ark_std::test_rng();

        const TEST_DST: &[u8] = b"PEDERSEN:BLS12-381";
        let generator_1_test = G1Projective::generator();
        let h_1_test = derive_h(TEST_DST);

        let r_1_test = Fr::rand(&mut rng);
        let r_2_test = Fr::rand(&mut rng);

        let m_1_test = Fr::from(2025);
        let m_2_test = Fr::from(1961);

        let commit_1 = commitment_generation(generator_1_test.clone(), h_1_test.clone(), r_1_test, m_1_test);
        let commit_2 = commitment_generation(generator_1_test.clone(), h_1_test.clone(), r_2_test, m_2_test);
        let commit_combined = commitment_generation(generator_1_test, h_1_test, r_2_test + r_1_test, m_2_test + m_1_test);

        assert_eq!(commit_combined, commit_1 + commit_2);
    }
}
