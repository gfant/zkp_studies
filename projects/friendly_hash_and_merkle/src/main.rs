use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::{test_rng, Zero};

fn poseidon(state: usize, full_rounds: usize, partial_rounds: usize, security_param: i32, state_vector: &[Fr]) -> Fr {
    Fr::from(0u64)
}

fn constant_vector(t: usize) -> Vec<Fr> {
    let mut rng = test_rng();
    let mut ci_vector = Vec::with_capacity(t);
    for _ in 0..t {
        ci_vector.push(Fr::rand(&mut rng));
    }
    ci_vector
}

fn mixing_matrix(size: usize) -> Vec<Vec<Fr>> {
    let u: Vec<Fr> = (1..=size).map(|x| Fr::from(x as u64)).collect();
    let v: Vec<Fr> = (size+1..=2*size).map(|x| Fr::from(x as u64)).collect();
    let mut matrix = vec![vec![Fr::zero(); size]; size];
    for wdx in 0..size {
        for hdx in 0..size {
            let diff = u[wdx] - v[hdx];
            let entry = diff.inverse().unwrap();
            matrix[hdx][wdx] = entry;
        }
    }
    matrix
}

fn main() {
    let t: usize = 3;
    let sec_param = 3;
    let full_rounds: usize = 10;
    let partial_rounds: usize = 5;

    let mut rng = ark_std::test_rng();
    let mut state_vector: Vec<Fr> = Vec::new();
    for _ in 0..t {
        state_vector.push(Fr::rand(&mut rng));
    }

    let ci_vector: Vec<Fr> = constant_vector(t);

    println!("State vector: {:?}", state_vector);

    //let poseidon_val = poseidon(t, sec_param);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verifying the homomorphism identity is correct.
    #[test]
    fn test_mixing_matrix() {
        let mut matrix = mixing_matrix(3);
        let mut entry_0_0 = (Fr::from(1u32) - Fr::from(4u32)).inverse().unwrap();
        assert_eq!(matrix.len(), 3, "Wrong sizes size 3");
        assert_eq!(matrix[0][0], entry_0_0, "Wrong entries size 3");
        
        let mut matrix = mixing_matrix(1);
        entry_0_0 = (Fr::from(1u32) - Fr::from(2u32)).inverse().unwrap();
        assert_eq!(matrix.len(), 1, "Wrong sizes size 1");
        assert_eq!(matrix[0][0], entry_0_0, "Wront entries size 1");
    }
}
