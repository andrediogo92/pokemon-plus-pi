use std::env::var;

fn main() {
    // The manifest dir points to the root of the project containing this file.
    let sysroot = var("SYSROOT").unwrap();
    // We tell Cargo that our native ARMv7 libraries are inside a "libraries" folder.
    println!("cargo:rustc-link-search={}", sysroot);
}