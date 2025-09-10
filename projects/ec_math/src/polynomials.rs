use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::PrimeGroup; // Allow mul_bigint in group elements
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use ark_std::Zero; // Allow zero from Fr

// Polynomials trait, polynomials can be generated from a vector/slice, polynomials are univariate
use ark_poly::{Polynomial, DenseUVPolynomial, univariate::DensePolynomial};

struct Commitment {
    value: G1Projective,
}

fn commit(poly: &DensePolynomial<Fr>, tau: Fr, g: G1Projective) -> Commitment {
    let eval = poly.evaluate(&tau);
    Commitment { value: g * eval }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_commit() {
        let generator = G1Projective::generator(); // G1 is a cyclic group, so it's isomorphic to an additive group
        // The order of the polynomial is inverted (7 is the highest, -4 the constant)
        let polynomial =
            DensePolynomial::from_coefficients_slice(&[Fr::from(-4i32), Fr::from(9u32), Fr::from(7u32)]);
        let tau = Fr::from(10u64);

        let exp = Fr::from(786u64);
        let expected = generator * exp; 
        let generated_commitment = commit(&polynomial, tau, generator);

        assert_eq!(generated_commitment.value, expected);
    }
}
