use rand::Rng;

// Executes k rounds of a "coin-flip challenge" protocol
// Returns true if cheating prover succeeds in fooling verifier
fn cheating_prover_simulation(k: u32) -> bool {
    let mut rng = rand::rng();
    // Cheating prover only guesses randomly each round
    for _ in 0..k {
        let guess: bool = rng.random(); // random guess
        let challenge: bool = rng.random(); // verifier’s challenge
        if guess != challenge {
            return false; // caught cheating
        }
    }
    true
}

fn main() {
    // Change the k. Remember the probability cheating becomes at most (1/2) ** k. So if the prob 
    let k = 4;
    let trials = 100_000;
    let mut success_count = 0;

    for _ in 0..trials {
        if cheating_prover_simulation(k) {
            success_count += 1;
        }
    }

    println!("Cheating prover succeeded {} times out of {}", success_count, trials);
}
