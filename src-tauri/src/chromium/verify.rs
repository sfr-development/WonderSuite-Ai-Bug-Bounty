use super::error::ChromiumError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Compute the SHA-256 of a file as a lowercase hex string.
pub fn sha256_file(path: &Path) -> Result<String, ChromiumError> {
    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify that the file at `path` hashes to `expected_hex` (case-insensitive).
/// Returns Ok(()) on match, ChromiumError::HashMismatch otherwise.
pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<(), ChromiumError> {
    let got = sha256_file(path)?;
    if got.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(ChromiumError::HashMismatch { expected: expected_hex.to_ascii_lowercase(), got })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashes_known_input() {
        let mut tmp = tempfile_path("ws-verify-test");
        let _ = std::fs::remove_file(&tmp);
        {
            let mut f = File::create(&tmp).unwrap();
            f.write_all(b"hello").unwrap();
        }
        // SHA-256 of "hello"
        let want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let got = sha256_file(&tmp).unwrap();
        assert_eq!(got, want);
        assert!(verify_sha256(&tmp, want).is_ok());
        assert!(verify_sha256(&tmp, "00".repeat(32).as_str()).is_err());
        let _ = std::fs::remove_file(&tmp);
        // touch tmp var to avoid unused warning
        let _ = &mut tmp;
    }

    fn tempfile_path(prefix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p
    }
}
