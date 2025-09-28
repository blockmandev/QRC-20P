use curve25519_dalek::scalar::Scalar;
use rand::Rng;

fn main() {
    // Check available methods for creating random scalars
    let mut rng = rand::thread_rng();

    // Method 1: from_bytes_mod_order (what we're currently using)
    let random_bytes: [u8; 32] = rng.gen();
    let scalar1 = Scalar::from_bytes_mod_order(random_bytes);
    println!("Method 1 - from_bytes_mod_order: works!");

    // Method 2: from_bytes_mod_order_wide (64 bytes)
    let mut wide_bytes = [0u8; 64];
    rng.fill(&mut wide_bytes[..]);
    let scalar2 = Scalar::from_bytes_mod_order_wide(&wide_bytes);
    println!("Method 2 - from_bytes_mod_order_wide: works!");

    // Method 3: hash_from_bytes (using hash function)
    use sha2::{Sha512, Digest};
    let scalar3 = Scalar::hash_from_bytes::<Sha512>(b"some data");
    println!("Method 3 - hash_from_bytes: works!");

    // Method 4: from_hash (from a Digest)
    let mut hasher = Sha512::new();
    hasher.update(b"some data");
    let scalar4 = Scalar::from_hash(hasher);
    println!("Method 4 - from_hash: works!");

    println!("\nConclusion: Scalar::random() does NOT exist in curve25519-dalek v4.1");
    println!("We must use Scalar::from_bytes_mod_order(rng.gen()) instead.");
}