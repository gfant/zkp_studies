use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{
    univariate::{DensePolynomial, SparsePolynomial},
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial,
};
use ark_std::{test_rng, UniformRand};

#[derive(Clone)]
struct ABC {
    a: DensePolynomial<Fr>,
    b: DensePolynomial<Fr>,
    c: DensePolynomial<Fr>,
    z: SparsePolynomial<Fr>,
    dom: GeneralEvaluationDomain<Fr>,
}

#[derive(Clone)]
struct AllPolys {
    a: DensePolynomial<Fr>,
    b: DensePolynomial<Fr>,
    c: DensePolynomial<Fr>,
    h: DensePolynomial<Fr>,
    r: DensePolynomial<Fr>,
    z: SparsePolynomial<Fr>,
    d: GeneralEvaluationDomain<Fr>,
}

fn generate_poly(coeffs: Vec<Fr>) -> DensePolynomial<Fr> {
    DensePolynomial::from_coefficients_vec(coeffs)
}

// Dot product for vectors from QAP with witness
fn dot(a: &[Fr], w: &[Fr]) -> Fr {
    let mut total = Fr::zero();
    for i in 0..a.len() {
        total += a[i] * w[i];
    }
    total
}

pub fn secret_value() -> Fr {
    let mut rng = test_rng();
    Fr::rand(&mut rng)
}

fn verify_r1cs(a_rows: Vec<Vec<Fr>>, b_rows: Vec<Vec<Fr>>, c_rows: Vec<Vec<Fr>>, w: Vec<Fr>) -> bool {
    let mut valid = true;
    for i in 0..a_rows.len() {
        let a_i = dot(&a_rows[i], &w);
        let b_i = dot(&b_rows[i], &w);
        let c_i = dot(&c_rows[i], &w);
        valid = a_i * b_i == c_i;
        let valid_eq = if valid { "SATISFIED" } else { "FAILED" };
        println!("  Constraint {}: {} * {} = {} -> {}", i + 1, a_i, b_i, c_i, valid_eq);
    }
    valid
}

fn produce_interpolations_abc(a_rows: Vec<Vec<Fr>>, b_rows: Vec<Vec<Fr>>, c_rows: Vec<Vec<Fr>>, w: Vec<Fr>) -> ABC {
    let size = a_rows.len();
    // Create evaluation domain for Lagrange interpolation
    let dom = GeneralEvaluationDomain::<Fr>::new(size).unwrap();

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

    let _witness_evals = Evaluations::from_vec_and_domain(w.to_vec(), dom);

    // For each column, create polynomial by interpolating its evaluations
    let mut a_polys = Vec::new();
    let mut b_polys = Vec::new();
    let mut c_polys = Vec::new();

    for col in 0..w.len() {
        let a_eval = Evaluations::from_vec_and_domain(a_evals[col].clone(), dom);
        let b_eval = Evaluations::from_vec_and_domain(b_evals[col].clone(), dom);
        let c_eval = Evaluations::from_vec_and_domain(c_evals[col].clone(), dom);

        a_polys.push(a_eval.interpolate());
        b_polys.push(b_eval.interpolate());
        c_polys.push(c_eval.interpolate());
    }

    // Compute A(X), B(X), C(X) as linear combinations with witness
    // A(X) = Σ w_i * A_i(X), B(X) = Σ w_i * B_i(X), C(X) = Σ w_i * C_i(X)
    let mut a = DensePolynomial::zero();
    let mut b = DensePolynomial::zero();
    let mut c = DensePolynomial::zero();

    for (i, &w_i) in w.iter().enumerate() {
        a = &a + &(&a_polys[i] * w_i);
        b = &b + &(&b_polys[i] * w_i);
        c = &c + &(&c_polys[i] * w_i);
    }

    let z: SparsePolynomial<Fr> = dom.vanishing_polynomial();

    ABC { a: a, b: b, c: c, z: z, dom: dom }
}

fn compute_prod_minus_polynomial(abc: ABC) -> DensePolynomial<Fr> {
    &abc.a * &abc.b - &abc.c
}

fn generate_all_polynomials(a_rows: Vec<Vec<Fr>>, b_rows: Vec<Vec<Fr>>, c_rows: Vec<Vec<Fr>>, w: Vec<Fr>) -> AllPolys {
    verify_r1cs(a_rows.clone(), b_rows.clone(), c_rows.clone(), w.clone());

    let interpolations = produce_interpolations_abc(a_rows, b_rows, c_rows, w);
    let prod_minus_c_poly = compute_prod_minus_polynomial(interpolations.clone());
    let division_result = prod_minus_c_poly.divide_by_vanishing_poly(interpolations.dom);
    let h_poly = division_result.0;
    let r_poly = division_result.1;

    AllPolys {
        a: interpolations.a,
        b: interpolations.b,
        c: interpolations.c,
        z: interpolations.z,
        h: h_poly,
        r: r_poly,
        d: interpolations.dom,
    }
}

fn groth_verification(all_polynomials: AllPolys) -> bool {
    let tau = secret_value();
    let alpha = secret_value();
    let beta = secret_value();

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    // Evaluating polynomials at tau
    let A_tau = all_polynomials.a.evaluate(&tau);
    let B_tau = all_polynomials.b.evaluate(&tau);
    let C_tau = all_polynomials.c.evaluate(&tau);
    let Z_tau = all_polynomials.z.evaluate(&tau);
    let H_tau = all_polynomials.h.evaluate(&tau);

    // First verify A(tau) * B(tau) = C(tau) + H(tau) * Z(tau)
    let left_side = A_tau * B_tau;
    let right_side = C_tau + H_tau * Z_tau;

    println!("A(tau) * B(tau) = {}", left_side);
    println!("C(tau) + H(tau) * Z(tau) = {}", right_side);
    println!("Basic constraint verification: {}", left_side == right_side);

    if left_side != right_side {
        println!("Basic constraint failed!");
        return false;
    }

    /*
        Now verify using alpha and beta with pairings
        It means:

        e(g1^(alpha + A(tau)), g2^(beta + B(tau))) = e(g1^alpha, g2^beta) * e(g1^A(tau), g2^B(tau)) * e(g1^(alpha*B(tau) + beta*A(tau)), g2)

    */

    // lhs
    let g1_alpha_plus_A = g1.mul_bigint((alpha + A_tau).into_bigint());
    let g2_beta_plus_B = g2.mul_bigint((beta + B_tau).into_bigint());

    // rhs first
    let g1_alpha = g1.mul_bigint(alpha.into_bigint());
    let g2_beta = g2.mul_bigint(beta.into_bigint());

    // rhs second
    let g1_A_tau = g1.mul_bigint(A_tau.into_bigint());
    let g2_B_tau = g2.mul_bigint(B_tau.into_bigint());

    // rhs third
    let g1_alpha_B_plus_beta_A = g1.mul_bigint((alpha * B_tau + beta * A_tau).into_bigint());

    // lhs pairing: e(g1^(alpha + A(tau)), g2^(beta + B(tau)))
    let lhs = Bls12_381::pairing(g1_alpha_plus_A, g2_beta_plus_B);

    // rhs side: e(g1^alpha, g2^beta) * e(g1^A(tau), g2^B(tau)) * e(g1^(alpha*B(tau) + beta*A(tau)), g2)
    let rhs_alpha_beta = Bls12_381::pairing(g1_alpha, g2_beta);
    let rhs_A_tau_B_tau = Bls12_381::pairing(g1_A_tau, g2_B_tau);
    let rhs_alpha_B_beta_A = Bls12_381::pairing(g1_alpha_B_plus_beta_A, g2);
    let rhs = rhs_alpha_beta + rhs_A_tau_B_tau + rhs_alpha_B_beta_A;

    let pairing_check = lhs == rhs;
    println!("Pairing verification with alpha and beta: {}", pairing_check);

    // Final Verification: Check that holds with alpha/beta blinding
    // This verifies: (alpha + A(tau)) * (beta + B(tau)) = alpha*beta + alpha*B(tau) + beta*A(tau) + A(tau)*B(tau)
    // Considering A(tau)*B(tau) = C(tau) + H(tau)*Z(tau)
    let blinded_lhs = (alpha + A_tau) * (beta + B_tau);
    let blinded_rhs = alpha * beta + alpha * B_tau + beta * A_tau + C_tau + H_tau * Z_tau;

    println!("\nFinal verification:");
    let final_check = blinded_lhs == blinded_rhs;
    println!("Alternative constraint holds: {}", final_check);

    let total_check = pairing_check && final_check;
    println!("Everything holds: {}", total_check);

    total_check
}

fn main() {
    // Sample equation: x^3 + x^2 -3x + 2
    let _coeffs = vec![Fr::from(1u64), Fr::from(1u64), Fr::zero() - Fr::from(3u64), Fr::from(2u64)];

    /*
    The equations a*b = c for this example are:

    (x + 1)(x)    = a_1
    (a_1 - 3)(x)  = a_2
    (a_2 + 2)(1)  = a_3

    So if w = (1,x,a_1,a_2,a_3), the equations are:

    (1,1,0,0,0) (0,1,0,0,0) = (0,0,1,0,0)
    (-3,0,1,0,0) (0,1,0,0,0) = (0,0,0,1,0)
    (2,0,0,1,0) (1,0,0,0,0) = (0,0,0,0,1)

    x is the private value
    a_1 = x^2 + x
    a_2 = x^3 + x^2 -3x
    a_3 = x^3 + x^2 -3x + 2

    */

    let a1 = vec![Fr::from(1), Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0)];
    let b1 = vec![Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0)];
    let c1 = vec![Fr::from(0), Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(0)];

    let a2 = vec![Fr::from(-3), Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(0)];
    let b2 = vec![Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0)];
    let c2 = vec![Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(1), Fr::from(0)];

    let a3 = vec![Fr::from(2), Fr::from(0), Fr::from(0), Fr::from(1), Fr::from(0)];
    let b3 = vec![Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)];
    let c3 = vec![Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(1)];

    // Generating the matrices we require
    let a_rows = vec![a1, a2, a3];
    let b_rows = vec![b1, b2, b3];
    let c_rows = vec![c1, c2, c3];

    /*
    a_rows:
    (1,1,0,0,0)
    (-3,0,1,0,0)
    (2,0,0,1,0)

    b_rows:
    (0,1,0,0,0)
    (0,1,0,0,0)
    (1,0,0,0,0)

    c_rows
    (0,0,1,0,0)
    (0,0,0,1,0)
    (0,0,0,0,1)
    */

    // Generating a witness vector
    let x = secret_value();
    let a_1 = x * x + x;
    let a_2 = (a_1 - Fr::from(3)) * x;
    let a_3 = a_2 + Fr::from(2u64);
    let w = vec![Fr::one(), x, a_1, a_2, a_3];

    let all_polynomials = generate_all_polynomials(a_rows, b_rows, c_rows, w);

    // Now testing
    let valid_groth16 = groth_verification(all_polynomials);
    println!("{}", valid_groth16);
}
