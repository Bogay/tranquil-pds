use rand::Rng;

pub fn generate_2fa_code() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(0..1_000_000);
    format!("{:06}", code)
}
