use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use blake2::Blake2s256;
use digest::Digest;

// Parameters used for Poseidon process
#[derive(Clone)]
struct Poseidon<F> {
    t: usize,                     // Size of m
    alpha: u128,                  // Power to which the sbox operation will exponentiate the entries
    number_full_rounds: usize,    // Times the f_round will be executed on the message
    number_partial_rounds: usize, // Times the p_round will be executed on the message
    mixing_matrix: Vec<Vec<F>>,   // Matrix that will be used for mutiplications in the rounds.
    constant_vector: Vec<Vec<F>>, // Constant matrix that will be used for additions in the rounds
}

// Formal way to hash the values for the constant vector.
// It hashes the entry position, the round running and a seed
fn hash_input<F: PrimeField>(i: usize, r: usize, seed: &[u8]) -> F {
    let mut hasher = Blake2s256::new();
    hasher.update(seed);
    hasher.update(r.to_le_bytes());
    hasher.update(i.to_le_bytes());
    let digest = hasher.finalize();

    // Convert digest → field element
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest[..32]);
    let fe = F::from_le_bytes_mod_order(&bytes);
    fe
}

// Generates the constant vector
fn constant_vector<F: PrimeField>(t: usize, r: usize, seed: &[u8]) -> Vec<Vec<F>> {
    let mut ci_vector = vec![vec![F::zero(); t]; r];
    for pos in 0..t {
        for round in 0..r {
            ci_vector[round][pos] = hash_input::<F>(round, pos, seed);
        }
    }
    ci_vector
}

// Generates the mixing matrix
fn mixing_matrix<F: PrimeField>(size: usize) -> Vec<Vec<F>> {
    let u: Vec<F> = (1..=size).map(|x| F::from(x as u64)).collect();
    let v: Vec<F> = (size + 1..=2 * size).map(|x| F::from(x as u64)).collect();
    let mut matrix = vec![vec![F::zero(); size]; size];
    for wdx in 0..size {
        for hdx in 0..size {
            let diff = u[wdx] - v[hdx];
            let entry = diff.inverse().unwrap();
            matrix[hdx][wdx] = entry;
        }
    }
    matrix
}

// Functions for Poseidon process
impl<F: PrimeField> Poseidon<F> {
    // Adds the constant constant_vector from the params of Poseidon into the msg
    pub fn add_constant_vector(&self, round: usize, m: &mut Vec<F>) {
        for idx in 0..self.t {
            m[idx] += self.constant_vector[round][idx];
        }
    }

    // Multiplies the msg with the mixing matrix
    pub fn multiply_mixing_matrix(&self, m: &mut Vec<F>) {
        let mut out = vec![F::zero(); self.t];
        for hdx in 0..self.t {
            for wdx in 0..self.t {
                out[hdx] += self.mixing_matrix[hdx][wdx] * m[wdx];
            }
        }
        *m = out;
    }

    // S-box operation for only the first entry of the msg (for partial rounds)
    pub fn sbox_partial_operation(&self, m: &mut Vec<F>) {
        m[0] = Poseidon::power(m[0], self.alpha);
    }

    // Fast exponentiation to accelerate with p
    pub fn power(val: F, p: u128) -> F {
        let mut power = p;
        let mut curr = val;
        let mut ans = F::one();
        while power > 0 {
            if power & 1 == 1 {
                ans = ans * curr;
            }
            curr = curr * curr;
            power >>= 1;
        }
        ans
    }

    // S-box operation for all the entries of the msg (for full rounds)
    pub fn sbox_full_operation(&self, m: &mut Vec<F>) {
        for idx in 0..self.t {
            m[idx] = Poseidon::power(m[idx], self.alpha);
        }
    }

    // Full round composition
    pub fn f_round(&self, round: usize, m: &mut Vec<F>) {
        self.add_constant_vector(round, m);
        self.sbox_full_operation(m);
        self.multiply_mixing_matrix(m);
    }

    // Partial round composition
    pub fn p_round(&self, round: usize, m: &mut Vec<F>) {
        self.add_constant_vector(round, m);
        self.sbox_partial_operation(m);
        self.multiply_mixing_matrix(m);
    }

    // Executes all the rounds as how poseidon requires.
    pub fn apply_rounds(&self, m: &mut Vec<F>) -> F {
        let half = self.number_full_rounds / 2;
        let mut round = 0;
        for _ in 0..half {
            self.f_round(round, m);
            round += 1;
        }
        for _ in 0..self.number_partial_rounds {
            self.p_round(round, m);
            round += 1;
        }
        for _ in 0..half {
            self.f_round(round, m);
            round += 1;
        }
        m[0]
    }
}

// Generates a Poseidon struct for doing the whole process
fn setup_poseidon<F:PrimeField>(t: usize, alpha: u128, number_full_rounds: usize, number_partial_rounds: usize, constant_vector: Vec<Vec<Fr>>) -> Poseidon<Fr> {
    Poseidon {
        t,
        alpha,
        number_full_rounds,
        number_partial_rounds,
        constant_vector: constant_vector,
        mixing_matrix: mixing_matrix(t),
    }
}

fn poseidon_hash<F:PrimeField>(inputs: &[F], rate: usize, outputs_size: usize, params: &Poseidon<F>) -> Vec<F> {
    let mut state = vec![F::zero(); params.t]; // Starts the state
    let mut idx = 0;
    while idx < inputs.len() {
        for r in 0..rate {
            let new_idx = idx + r;
            if new_idx < inputs.len() {
                state[r] += inputs[new_idx];
            }
        }
        params.apply_rounds(&mut state);
        idx += rate;
    }

    let mut output = Vec::with_capacity(outputs_size);
    while output.len() < outputs_size {
        // While we require entries
        for r in 0..rate {
            // Get the rates
            if output.len() == outputs_size {
                // Stop adding entries if obtained the required entries
                break;
            }
            output.push(state[r]);
        }
        if output.len() < outputs_size {
            // Permute once you add your rate of entries
            params.apply_rounds(&mut state);
        }
    }
    output
}

fn main() {
    let rate = 2;
    let outputs_size = 5;

    let t = 3;
    let number_full_rounds = 8;
    let number_partial_rounds = 56;
    let alpha = 5;
    let constants = constant_vector::<Fr>(t, number_full_rounds + number_partial_rounds, b"poseidon");
    let poseidon = setup_poseidon::<Fr>(t, alpha, number_full_rounds, number_partial_rounds, constants);

    // Vector to apply the Poseidon method
    let mut message = vec![Fr::from(2025u64), Fr::from(2026u64), Fr::from(2027u64)];
    let poseidon_message_explicit = poseidon_hash(&message, rate, outputs_size, &poseidon);
    let poseidon_message_wrapper = poseidon.apply_rounds(&mut message);

    println!("Poseidon output (wrapper): {:?}", poseidon_message_wrapper);
    println!("Poseidon output (explicit): {:?}", poseidon_message_explicit);
}

// Testing
#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field};

    // Verifying the homomorphism identity is correct.
    #[test]
    fn test_mixing_matrix() {
        let matrix = mixing_matrix::<Fr>(3);
        let mut entry_0_0 = (Fr::from(1u32) - Fr::from(4u32)).inverse().unwrap();
        assert_eq!(matrix.len(), 3, "Wrong sizes size 3");
        assert_eq!(matrix[0][0], entry_0_0, "Wrong entries size 3");

        let matrix = mixing_matrix::<Fr>(1);
        entry_0_0 = (Fr::from(1u32) - Fr::from(2u32)).inverse().unwrap();
        assert_eq!(matrix.len(), 1, "Wrong sizes size 1");
        assert_eq!(matrix[0][0], entry_0_0, "Wront entries size 1");
    }

    // Verifies the determinism of Poseidon process
    #[test]
    fn test_poseidon_determinism() {
        let t = 3;
        let number_full_rounds = 8 as usize;
        let number_partial_rounds = 56 as usize;
        let alpha = 5;
        let constants = constant_vector::<Fr>(t, number_full_rounds + number_partial_rounds, b"poseidon");
        let poseidon = setup_poseidon::<Fr>(t, alpha, number_full_rounds, number_partial_rounds, constants);

        let mut msg1 = vec![Fr::from(2025u64); 3];
        let mut msg2 = vec![Fr::from(2025u64); 3];
        assert_eq!(poseidon.apply_rounds(&mut msg1), poseidon.apply_rounds(&mut msg2), "Wrapper not working");
    }
}
