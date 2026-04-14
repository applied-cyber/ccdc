use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BASH_VERSION: &str = "5.2.37";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bash_binary = out_dir.join("bash");

    // Skip rebuild if the binary already exists (cached by cargo).
    if bash_binary.exists() {
        println!("cargo::rerun-if-changed=build.rs");
        return;
    }

    let tarball = download_bash(&out_dir);
    let src_dir = extract_bash(&out_dir, &tarball);
    build_bash(&src_dir, &bash_binary);

    assert!(
        bash_binary.exists(),
        "bash binary not found after build at {}",
        bash_binary.display()
    );

    verify_static(&bash_binary);

    println!("cargo::rerun-if-changed=build.rs");
}

fn download_bash(out_dir: &Path) -> PathBuf {
    let filename = format!("bash-{BASH_VERSION}.tar.gz");
    let tarball = out_dir.join(&filename);

    if tarball.exists() {
        return tarball;
    }

    let url = format!("https://ftp.gnu.org/gnu/bash/{filename}");
    eprintln!("build.rs: downloading {url}");

    let status = Command::new("curl")
        .args(["-sSfL", "-o"])
        .arg(&tarball)
        .arg(&url)
        .status()
        .expect("failed to run curl — is curl installed?");

    assert!(status.success(), "curl failed to download bash tarball");
    tarball
}

fn extract_bash(out_dir: &Path, tarball: &Path) -> PathBuf {
    let src_dir = out_dir.join(format!("bash-{BASH_VERSION}"));

    if src_dir.exists() {
        fs::remove_dir_all(&src_dir).expect("failed to clean old bash source dir");
    }

    eprintln!("build.rs: extracting {}", tarball.display());

    let status = Command::new("tar")
        .args(["xf"])
        .arg(tarball)
        .arg("-C")
        .arg(out_dir)
        .status()
        .expect("failed to run tar");

    assert!(status.success(), "tar extraction failed");
    assert!(src_dir.join("configure").exists(), "configure not found after extraction");
    src_dir
}

fn build_bash(src_dir: &Path, output: &Path) -> () {
    let nproc = Command::new("nproc")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "4".to_string());

    eprintln!("build.rs: configuring bash (static, musl)");

    let configure_status = Command::new("./configure")
        .current_dir(src_dir)
        .env("CC", "musl-gcc")
        .env("CFLAGS", "-Os -std=gnu17 -Wno-error=implicit-function-declaration")
        .args([
            "--without-bash-malloc",
            "--enable-static-link",
            "--disable-nls",
            "--host=x86_64-linux-musl",
        ])
        .status()
        .expect("failed to run bash configure — are autoconf and musl-tools installed?");

    assert!(configure_status.success(), "bash configure failed");

    eprintln!("build.rs: building bash with {nproc} jobs");

    let make_status = Command::new("make")
        .current_dir(src_dir)
        .arg(format!("-j{nproc}"))
        .status()
        .expect("failed to run make");

    assert!(make_status.success(), "bash make failed");

    let built = src_dir.join("bash");
    assert!(
        built.exists(),
        "bash binary not produced by make at {}",
        built.display()
    );

    fs::copy(&built, output).expect("failed to copy bash binary to OUT_DIR");

    // Strip the binary to reduce size.
    let _ = Command::new("strip")
        .arg(output)
        .status();

    let size = fs::metadata(output).unwrap().len();
    eprintln!(
        "build.rs: static bash ready at {} ({:.1} MiB)",
        output.display(),
        size as f64 / (1024.0 * 1024.0)
    );
}

fn verify_static(binary: &Path) {
    let output = Command::new("file")
        .arg(binary)
        .output()
        .expect("failed to run file command");

    let desc = String::from_utf8_lossy(&output.stdout);
    assert!(
        desc.contains("statically linked"),
        "bash binary is not statically linked: {desc}"
    );
}
