use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::PrimeGroup; // Allow mul_bigint in group elements
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use ark_std::Zero; // Allow zero from Fr

pub fn pairing_generator(p: G1Projective, q: G2Projective) -> PairingOutput<Bls12_381> {
    Bls12_381::pairing(p, q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn pairing_properties() {
        let mut rng = StdRng::seed_from_u64(2025);
        // Groups G1 G2 to project into the multiplicative group
        let a = G1Projective::rand(&mut rng);
        let b = G2Projective::rand(&mut rng);
        
        // Scalars
        let q = Fr::rand(&mut rng);
        let p = Fr::rand(&mut rng);

        // Getting the pairing for a*p and b*q. THIS IS AN ELEMENT, NOT A FUNCTION
        let inside_power = pairing_generator(a * p, b * q);

        let eab = pairing_generator(a, b);
        let exp = (p*q).into_bigint();
        let eab_powered = eab.0.pow(exp);
        // Return it into a PairingOutput to compare
        let outside_power = PairingOutput::<Bls12_381>(eab_powered);

        // Compare pairing Output
        assert_eq!(inside_power, outside_power);
        // Compare elements
        assert_eq!(eab_powered, inside_power.0);
    }
}
