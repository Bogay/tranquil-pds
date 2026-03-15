use std::process::Command;

fn main() {
    let timestamp = Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S UTC")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
    println!("cargo:rerun-if-changed=build.rs");
}
