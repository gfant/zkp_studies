use num_bigint::BigUint;
use rand::Rng;

fn gen_h(g: &BigUint, w: &BigUint, p: &BigUint) -> BigUint {
    g.modpow(w, p)
}

// Prover knows w, public is g, h = g^w mod p (Discrete Logarithm Problem)
fn discrete_log_sigma_protocol(p: &BigUint, g: &BigUint, w: &BigUint) {

    let h = gen_h(g, w, p);
    let one = BigUint::from(1u32);
    let q = p - &one; // p is prime so the. multiplicative group Zx is of ord of the group is p-1. 

    // take a random value generator
    let mut rng = rand::rng();

    // Commitment: Take a random val and send g ** r mod p
    let r = BigUint::from(rng.random::<u32>()) % &q;
    let a = g.modpow(&r, p);
    
    // Verifier challenge: Send a random e for the challenge
    let e = BigUint::from(rng.random::<u32>()) % &q;

    // Response: Prover computes z = r + ew mod p and returns it.
    let z = (&r + &(&e * w)) % &q;

    // Verification: Check if it's valid the response.
    let lhs = g.modpow(&z, p);
    let rhs = (a * h.modpow(&e, p)) %p;

    println!("Check passed: {}\nValues obtained:\n\tleft: {}\t right:{}", lhs == rhs, lhs, rhs);
}



fn main(){
    let p = BigUint::from(100_000_007u32);
    let g = BigUint::from(123123u32);
    let w = BigUint::from(444u32);
    
    discrete_log_sigma_protocol(&p, &g, &w);
}
