use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;

    // Try to use Scalar::random
    // This will fail to compile if it doesn't exist
    let _scalar = Scalar::random(&mut rng);

    println!("Scalar::random exists!");
}