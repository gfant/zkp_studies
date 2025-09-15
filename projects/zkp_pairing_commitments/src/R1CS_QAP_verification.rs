use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{PrimeField, Zero, One};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_std::{test_rng, UniformRand};

/// tau is a random element in the SCALAR FIELD Fr
pub fn generate_secret() -> Fr {
    let mut rng = test_rng();
    Fr::rand(&mut rng)
}

/// Commit g1^{f(tau)} using [g1^{tau^i} for i in [0..d]
fn commit_g1_f_of_tau(poly: &DensePolynomial<Fr>, crs_g1: &[G1Projective]) -> G1Projective {
    poly.coeffs
        .iter()
        .enumerate()
        .fold(G1Projective::zero(), |acc, (i, a_i)| if a_i.is_zero() { acc } else { acc + crs_g1[i].mul_bigint(a_i.into_bigint()) })
}

/// Commit g2^{f(tau)} using [g2^{tau^i} for i in 0..d]
fn commit_g2_f_of_tau(poly: &DensePolynomial<Fr>, crs_g2: &[G2Projective]) -> G2Projective {
    poly.coeffs
        .iter()
        .enumerate()
        .fold(G2Projective::zero(), |acc, (i, a_i)| if a_i.is_zero() { acc } else { acc + crs_g2[i].mul_bigint(a_i.into_bigint()) })
}

// Dot product for vectors from QAP with witness
fn dot(a: &[Fr], w: &[Fr]) -> Fr {
    let mut total = Fr::zero();
    for i in 0..a.len() {
        total += a[i] * w[i];
    }
    total
}

fn main() {
    println!("ZKP Pairing\n");

    // Step 1: Generate values G1, G2, GT

    // Generators for groups G1 and G2 in BLS12-381 curve
    // G1 and G2 are additive groups (we use + for group operation)
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    // Compute a generator for the target group GT using the bilinear pairing (in this case BLS12_381)
    // GT is a multiplicative group (Operation is * for group)
    // The pairing e: G1 × G2 -> GT is bilinear: e(g1^a, g2^b) = e(g1, g2)^(ab)
    let _gt = Bls12_381::pairing(g1, g2);

    // STEP 2: Generating Trusted Setup

    // Generate a random secret value tau (the "toxic waste")
    // In a real setup, this would be generated in a trusted ceremony and then destroyed
    let tau = generate_secret();

    // Target polynomial: f(x) = 7x^2 + 9x - 4
    // Note: coefficients are in ascending order [constant, x, x^2 ]
    let polynomial = DensePolynomial::from_coefficients_vec(vec![
        Fr::from(-4i32), // constant
        Fr::from(9u32),  // x
        Fr::from(7u32),  // x^2
    ]);

    let degree = polynomial.degree();
    println!("Polynomial degree: {}", degree); // Just for verifying everything is ok

    // Create the Common Reference String (CRS)
    // CRS contains powers of tau in both G1 and G2 groups: [g^1, g^(tau^1), g^(tau^2), ..., g^(tau^n)]
    // This allows us to compute commitments to polynomials without knowing tau
    // We need a larger CRS to handle the interpolated polynomials which will have higher degrees
    let max_degree = 10; // Sufficient for our constraint system
    let mut crs_g1: Vec<G1Projective> = Vec::with_capacity(max_degree + 1);
    let mut crs_g2: Vec<G2Projective> = Vec::with_capacity(max_degree + 1);

    // Initialize tau_pow to track powers of tau (starting with tau^0 = 1)
    let mut tau_pow = Fr::from(1u64);

    // Generate the CRS: [g^1, g^(tau^1), g^(tau^2), ..., g^(tau^n)] for g = g1, g2.
    for _i in 0..=max_degree {
        // Compute g1^(tauⁱ) and g2^(tauⁱ)
        let g1_powered = g1.mul_bigint(tau_pow.into_bigint());
        let g2_powered = g2.mul_bigint(tau_pow.into_bigint());

        crs_g1.push(g1_powered);
        crs_g2.push(g2_powered);

        tau_pow *= tau;
    }

    // STEP 3: COMPUTE POLYNOMIAL COMMITMENTS

    // Evaluate the polynomial at the secret tau
    let poly_at_tau = polynomial.evaluate(&tau);
    println!("Polynomial f(tau) = {}", poly_at_tau);

    // Compute commitments: g1^f(tau) and g2^f(tau)
    // These are polynomial commitments that hide the polynomial but allow verification
    let g1ftau = commit_g1_f_of_tau(&polynomial, &crs_g1);
    let g2ftau = commit_g2_f_of_tau(&polynomial, &crs_g2);

    // STEP 4: CONSTRAINT SYSTEM DECOMPOSITION

    /*
    GOAL: Convert f(x) = 7x² + 9x - 4 into a constraint system

    We decompose the polynomial into intermediate steps:
    f(x) = 7x^2 + 9x - 4 can be rewritten as:

    a = 7x + 9
    b = x * a
    c = b - 4

    This gives us: c = x(7x + 9) - 4 = 7x^2 + 9x - 4 = f(x)
    */

    // Choose a specific value for x to create our witness
    // In a real ZKP, this would be the secret input we want to prove knowledge of
    let x = Fr::from(1u64);
    println!("Using witness value x = {}", x);

    // Compute gates following our decomposition
    let a = Fr::from(7u32) * x + Fr::from(9u64); // a = 7x + 9 = 7(1) + 9 = 16
    let b = x * a; // b = x * a = 1 * 16 = 16
    let c = b - Fr::from(4u32); // c = b - 4 = 16 - 4 = 12

    println!("\ta = 7x + 9 = {}", a);
    println!("\tb = x * a = {}", b);
    println!("\tc = b - 4 = {}", c);

    // Witness vector w = [1, x, a, b, c]
    let w = [Fr::from(1u64), x, a, b, c];
    println!("Witness vector w = {:?}", w);

    /*
    CONSTRAINT SYSTEM FORMULATION:

    We need to express each equation as: <A_i, w> * <B_i, w> = <C_i, w>
    where A_i, B_i, C_i are selector vectors that pick out the right elements from w

    Our witness vector is: w = [1, x, a, b, c] (indices 0, 1, 2, 3, 4)

    a = 7x + 9
    - Left:   7x + 9 = <[9, 7, 0, 0, 0], w>
    - Right:  1      = <[1, 0, 0, 0, 0], w>
    - Equal:  a      = <[0, 0, 1, 0, 0], w>

    b = x * a
    - Left:   x      = <[0, 1, 0, 0, 0], w>
    - Right:  a      = <[0, 0, 1, 0, 0], w>
    - Equal:  b      = <[0, 0, 0, 1, 0], w>

    c = b - 4
    - Left:   b - 4  = <[-4, 0, 0, 1, 0], w>
    - Right:  1      = <[1, 0, 0, 0, 0], w>
    - Equal:  c      = <[0, 0, 0, 0, 1], w>
    */

    // (7x + 9) * 1 = a
    let a1 = [Fr::from(9u32), Fr::from(7u32), Fr::zero(), Fr::zero(), Fr::zero()]; // 7x + 9
    let b1 = [Fr::from(1u32), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()]; // 1
    let c1 = [Fr::zero(), Fr::zero(), Fr::from(1u64), Fr::zero(), Fr::zero()]; // a

    // x * a = b
    let a2 = [Fr::zero(), Fr::from(1u64), Fr::zero(), Fr::zero(), Fr::zero()]; // x
    let b2 = [Fr::zero(), Fr::zero(), Fr::from(1u64), Fr::zero(), Fr::zero()]; // a
    let c2 = [Fr::zero(), Fr::zero(), Fr::zero(), Fr::from(1u64), Fr::zero()]; // b

    // (b - 4) * 1 = c
    let a3 = [Fr::from(0u64) - Fr::from(4u64), Fr::zero(), Fr::zero(), Fr::from(1u64), Fr::zero()]; // b - 4
    let b3 = [Fr::from(1u32), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()]; // 1
    let c3 = [Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::from(1u64)]; // c

    let a_rows = vec![a1, a2, a3];
    let b_rows = vec![b1, b2, b3];
    let c_rows = vec![c1, c2, c3];

    for (i, ((a_row, b_row), c_row)) in a_rows.iter().zip(b_rows.iter()).zip(c_rows.iter()).enumerate() {
        // Iterate over each vector ai,bi,ci, and does dot product with the w witness vector
        let a_i = dot(&a_rows[i], &w);
        let b_i = dot(&b_rows[i], &w);
        let c_i = dot(&c_rows[i], &w);
        let valid_equation = a_i * b_i == c_i;
        let valid = if valid_equation { "SATISFIED" } else { "FAILED" };
        println!("  Constraint {}: {} * {} = {} -> {}", i + 1, a_i, b_i, c_i, valid);
    }

    println!("\nLAGRANGE INTERPOLATION SETUP");
    
    let size = a_rows.len();
    // Create evaluation domain for Lagrange interpolation
    let dom = GeneralEvaluationDomain::<Fr>::new(size).unwrap();

    // Extract evaluation points from the domain
    let domain_elements: Vec<Fr> = dom.elements().collect();

    // Create polynomials A(X), B(X), C(X) for each column of A,B and C.

    // Create evaluations for each column of the A, B, C matrices
    let mut a_evals = Vec::new();
    let mut b_evals = Vec::new();
    let mut c_evals = Vec::new();

    // For each witness element (column), collect its coefficients across all constraints (rows)
    for col in 0..w.len() {
        let mut a_col = Vec::new();
        let mut b_col = Vec::new();
        let mut c_col = Vec::new();

        for row in 0..size {
            a_col.push(a_rows[row][col]);
            b_col.push(b_rows[row][col]);
            c_col.push(c_rows[row][col]);
        }

        a_evals.push(a_col);
        b_evals.push(b_col);
        c_evals.push(c_col);
    }

    // Compute the witness polynomial W(X) by interpolating the witness vector
    let witness_evals = Evaluations::from_vec_and_domain(w.to_vec(), dom);
    let W = witness_evals.interpolate();
    println!("\n=== Witness Polynomial ===");
    println!("Witness polynomial W(X) coefficients: {:?}", W.coeffs);

    // For each column, create polynomial by interpolating its evaluations
    let mut A_polys = Vec::new();
    let mut B_polys = Vec::new();
    let mut C_polys = Vec::new();

    for col in 0..w.len() {
        let a_eval = Evaluations::from_vec_and_domain(a_evals[col].clone(), dom);
        let b_eval = Evaluations::from_vec_and_domain(b_evals[col].clone(), dom);
        let c_eval = Evaluations::from_vec_and_domain(c_evals[col].clone(), dom);

        A_polys.push(a_eval.interpolate());
        B_polys.push(b_eval.interpolate());
        C_polys.push(c_eval.interpolate());
    }

    // Compute A(X), B(X), C(X) as linear combinations with witness
    // A(X) = Σ w_i * A_i(X), B(X) = Σ w_i * B_i(X), C(X) = Σ w_i * C_i(X)
    let mut A = DensePolynomial::zero();
    let mut B = DensePolynomial::zero();
    let mut C = DensePolynomial::zero();

    for (i, &w_i) in w.iter().enumerate() {
        A = &A + &(&A_polys[i] * w_i);
        B = &B + &(&B_polys[i] * w_i);
        C = &C + &(&C_polys[i] * w_i);
    }

    println!("\nResulting Polynomials");
    println!("\nA(X) coefficients: {:?}", A.coeffs);
    println!("\nB(X) coefficients: {:?}", B.coeffs);
    println!("\nC(X) coefficients: {:?}", C.coeffs);

    // Vanishing polynomial Z(X) = X^n - 1 for domain of size n
    let Z = dom.vanishing_polynomial();

    // Verify constraint: A(X) * B(X) - C(X) should be divisible by Z(X)
    let prod_minus_c = &A * &B - &C;
    println!("\nP(X) = A(X) * B(X) - C(X) coefficients: {:?}", prod_minus_c.coeffs);

    // H = (A * B - C) / Z  with remainder 0 for valid witness
    // Remember T(x) = A(x) * B(x) - C(x), and since Z(x) | T(x), H(x) exists.
    let division_result = prod_minus_c.divide_by_vanishing_poly(dom);
    let h_poly = division_result.0;
    let r_poly = division_result.1;
    println!("\nQuotient H(X) coefficients: {:?}", &h_poly.coeffs);
    println!("Remainder R(X) coefficients: {:?}", r_poly.coeffs);
    
    assert!(r_poly.is_zero(), "Invalid witness: remainder != 0");    

        println!("\nPAIRING CHECK");

    // Convert sparse polynomial Z to dense polynomial for commitment
    // Z(X) = X^n - 1 where n is the domain size
    let domain_size = dom.size();
    let mut z_coeffs = vec![Fr::zero(); domain_size + 1];
    z_coeffs[0] = -Fr::one(); // constant term: -1
    z_coeffs[domain_size] = Fr::one(); // X^n term: 1
    let Z_dense = DensePolynomial::from_coefficients_vec(z_coeffs);

    // Commit A(tau), B(tau), C(tau), H(tau), Z(tau) with CRS
    let A_tau_g1 = commit_g1_f_of_tau(&A, &crs_g1);
    let B_tau_g2 = commit_g2_f_of_tau(&B, &crs_g2);
    let C_tau_g1 = commit_g1_f_of_tau(&C, &crs_g1);
    let H_tau_g1 = commit_g1_f_of_tau(&h_poly, &crs_g1);
    let Z_tau_g2 = commit_g2_f_of_tau(&Z_dense, &crs_g2);

    // Pairing check: e(A(tau), B(tau)) = e(C(tau), g2) + e(H(tau), Z(tau)).
    // Left-hand side: e(A(tau), B(tau)). 
    let lhs = Bls12_381::pairing(A_tau_g1, B_tau_g2);

    // Right-hand side: e(C(tau), g2) + e(H(tau), Z(tau))
    // Note: In GT (target group), the operation is multiplication, not addition
    // But we compute each pairing separately and then multiply the results
    let pairing_c_g2 = Bls12_381::pairing(C_tau_g1, g2);
    let pairing_h_z = Bls12_381::pairing(H_tau_g1, Z_tau_g2);
    let rhs = pairing_c_g2 + pairing_h_z;

    println!("LHS (A(tau) * B(tau)): {:?}", lhs);
    println!("RHS (C(tau) + H(tau) * Z(tau)): {:?}", rhs);

    if lhs == rhs {
        println!("Pairing equation holds: e(A(tau), B(tau)) = e(C(tau), g2) + e(H(tau), Z(tau))");
    } else {
        println!("Pairing equation failed!");
    }
}
