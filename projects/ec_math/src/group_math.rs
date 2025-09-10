use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup; // Allow mul_bigint in group elements
use ark_ff::PrimeField;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::Zero; // Allow zero from Fr

// Groups and points
pub fn scalar_prod(scalar: Fr, base: G1Projective) -> G1Projective {
    base * scalar
}

pub fn add_points(p: G1Projective, q: G1Projective) -> G1Projective {
    p + q
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_ec_group_addition() {
        let mut rng = StdRng::seed_from_u64(42);
        let a = G1Projective::rand(&mut rng);
        let b = G1Projective::rand(&mut rng);
        let c = G1Projective::rand(&mut rng);
        let left = add_points(add_points(a, b), c);
        let right = add_points(a, add_points(b, c));

        // Associative property
        assert_eq!(left, right);

        // Inverses
        let zero = add_points(a, -a);
        assert!(zero.is_zero());

        // Identity
        assert!(add_points(zero, zero).is_zero());
    }

    #[test]
    fn test_ec_group_scalar() {
        let mut rng = StdRng::seed_from_u64(42);
        let a = G1Projective::rand(&mut rng);

        // Any elem to the group order is the identity
        let group_order = Fr::MODULUS;
        let id = a.mul_bigint(group_order);
        assert!(id.is_zero());

        // Simple validation of scalar prod with equivalent sum
        assert_eq!(scalar_prod(Fr::from(3u64), a), a + a + a);
    }
}
