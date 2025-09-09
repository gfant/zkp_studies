use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

#[derive(Debug, Clone, PartialEq)]
pub struct DensePoly {
    pub coeffs: Vec<Fr>,
}

impl DensePoly {
    pub fn reduce(&mut self) {
        while self.coeffs.last().map_or(false, |c| c.is_zero()) {
            self.coeffs.pop();
        }
    }

    pub fn eval(self, x: Fr) -> Fr {
        let mut answer = Fr::zero();
        let size = self.coeffs.len();
        let mut last_pow = Fr::one();
        for idx in 0..size {
            answer += self.coeffs[idx] * last_pow;
            last_pow = last_pow * x;
        }
        answer
    }
}

pub fn add_poly(a: DensePoly, b: DensePoly) -> DensePoly {
    // Get sizes of polynomials
    let size_a: usize = a.coeffs.len();
    let size_b: usize = b.coeffs.len();
    // Define biggest and smallest
    let size: usize = size_a.max(size_b);
    // New polynomial entries
    let mut new_coeffs = vec![Fr::zero(); size];
    // Adding the entries
    for adx in 0..size {
        let a_coeff = if a.coeffs.get(adx).is_some() {
            a.coeffs[adx]
        } else {
            Fr::zero()
        };
        let b_coeff = if b.coeffs.get(adx).is_some() {
            b.coeffs[adx]
        } else {
            Fr::zero()
        };
        new_coeffs[adx] = a_coeff + b_coeff;
    }
    // New generated polynomial with added coefficients.
    let mut new_polynomial = DensePoly { coeffs: new_coeffs };
    new_polynomial.reduce();
    new_polynomial
}

pub fn prod_poly(a: DensePoly, b: DensePoly) -> DensePoly {
    let size_a: usize = a.coeffs.len();
    let size_b: usize = b.coeffs.len();

    if size_a == 0 as usize || size_b == 0 as usize {
        return DensePoly { coeffs: vec![] };
    }

    let size: usize = size_a + size_b - 1;
    let mut new_coeffs = vec![Fr::zero(); size];

    for adx in 0..size_a {
        for bdx in 0..size_b {
            new_coeffs[adx + bdx] += a.coeffs[adx] * b.coeffs[bdx];
        }
    }
    let mut new_polynomial = DensePoly { coeffs: new_coeffs };
    new_polynomial.reduce();
    new_polynomial
}

pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Fr {
    if bytes.len() == 0 {
        return Fr::zero();
    }
    Fr::from_le_bytes_mod_order(bytes)
}

pub fn to_le_bytes(x: &Fr) -> [u8; 32] {
    let v = x.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

pub fn invert(n: Fr) -> Option<Fr> {
    n.inverse()
}

#[cfg(test)]
mod tests {
    use super::*;

    const R_LE: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0x02, 0xA4, 0xBD,
        0x53, 0x05, 0xD8, 0xA1, 0x09, 0x08, 0xD8, 0x39, 0x33, 0x48, 0x7D, 0x9D, 0x29, 0x53, 0xA7,
        0xED, 0x73,
    ];
    const R_PLUS_1_LE: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0x02, 0xA4, 0xBD,
        0x53, 0x05, 0xD8, 0xA1, 0x09, 0x08, 0xD8, 0x39, 0x33, 0x48, 0x7D, 0x9D, 0x29, 0x53, 0xA7,
        0xED, 0x73,
    ];

    #[test]
    fn finite_field_small_endians() {
        let x = Fr::from(300u64);
        let x_hex = [0x2C, 0x01];
        let y_18_hex = [0x12];
        let y_18 = Fr::from(18u64);
        let zero = [0x00];
        assert_eq!(from_le_bytes_mod_order(&[]), Fr::zero());
        assert_eq!(from_le_bytes_mod_order(&zero), Fr::zero());
        assert_eq!(from_le_bytes_mod_order(&y_18_hex), y_18);
        assert_eq!(from_le_bytes_mod_order(&x_hex), x);
        assert_ne!(from_le_bytes_mod_order(&y_18_hex), Fr::from(17u64));
    }

    #[test]
    fn finite_field_overflowing_endians() {
        assert_eq!(from_le_bytes_mod_order(&R_LE), Fr::zero());
        assert_eq!(from_le_bytes_mod_order(&R_PLUS_1_LE), Fr::one());
    }

    #[test]
    fn roundtrip_small_values() {
        let vals = [0u64, 1, 17, 255, 256, 300, u64::MAX];
        for &n in vals.iter() {
            let x = Fr::from(n);
            let bytes = to_le_bytes(&x);
            let y = Fr::from_le_bytes_mod_order(&bytes);
            assert_eq!(x, y, "roundtrip failed for {n}");
        }
    }

    #[test]
    fn roundtrip_random_values() {
        use rand::Rng;
        let mut rng = rand::rng();
        for _ in 0..10 {
            let n: u64 = rng.random();
            let x = Fr::from(n);
            let bytes = to_le_bytes(&x);
            let y = Fr::from_le_bytes_mod_order(&bytes);
            assert_eq!(x, y, "roundtrip failed for random {n}");
        }
    }

    #[test]
    fn inverses() {
        assert_eq!(invert(Fr::one()), Some(Fr::one()));
        let rand_val = rand::random::<u64>();
        println!("{}", rand_val);

        let x = Fr::from(rand_val);
        let x_invert = invert(x).unwrap();
        assert_eq!(x * x_invert, Fr::one())
    }

    #[test]
    fn add_polynomials() {
        let poly_1 = DensePoly {
            coeffs: vec![Fr::from(1u64); 3],
        };
        let poly_0 = DensePoly {
            coeffs: vec![Fr::from(0u64); 1],
        };
        let poly_2 = DensePoly {
            coeffs: vec![Fr::from(2u64); 3],
        };
        assert_eq!(add_poly(poly_1.clone(), poly_0.clone()), poly_1);
        assert_eq!(add_poly(poly_1.clone(), poly_1.clone()), poly_2);
    }

    #[test]
    fn evaluating_polynomial() {
        let poly_1 = DensePoly {
            coeffs: vec![Fr::from(1u64); 3],
        };
        let result_eval = Fr::from(931u64);
        assert_eq!(poly_1.eval(Fr::from(30u64)), result_eval)
    }

    #[test]
    fn mult_polynomials() {
        let poly_1 = DensePoly {
            coeffs: vec![Fr::from(1u64); 3],
        };
        let poly_prod = DensePoly {
            coeffs: vec![
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(2u64),
                Fr::from(1u64),
            ],
        };
        let poly_0 = DensePoly { coeffs: vec![] };
        assert_eq!(prod_poly(poly_1.clone(), poly_1.clone()), poly_prod);
        assert_eq!(prod_poly(poly_1.clone(), poly_0.clone()), poly_0);
    }
}
