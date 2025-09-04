fn main() {
    let p = 17;
    let a = finite_math::Fp::new(5, p);
    let b = finite_math::Fp::new(3, p);

    println!("a + b = {:?}", a + b);
    println!("a - b = {:?}", a - b);
    println!("a * b = {:?}", a * b);
    println!("a^-1 = {:?}", a.inverse());
}