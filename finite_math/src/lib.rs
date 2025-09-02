use std::ops::{Add, Sub, Mul};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fp {
    value: u64,
    modulus: u64,
}

impl Fp {
    pub fn new(value: u64, modulus: u64) -> Self {
        Self { value: value % modulus, modulus }
    }

    pub fn inverse(&self) -> Self {
        // Fermat's little theorem: a^(p-2) mod p = a^-1
        Self::new(mod_exp(self.value, self.modulus - 2, self.modulus), self.modulus)
    }
}

fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp /= 2;
    }
    result
}

// Implement Add, Sub, Mul for field elements
impl Add for Fp {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Fp::new((self.value + rhs.value) % self.modulus, self.modulus)
    }
}

impl Sub for Fp {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Fp::new((self.value + self.modulus - rhs.value) % self.modulus, self.modulus)
    }
}

impl Mul for Fp {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Fp::new((self.value * rhs.value) % self.modulus, self.modulus)
    }
}