use dashmap::DashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

/// Enterprise Certificate Authority using OpenSSL CLI.
/// Auto-discovers OpenSSL from PATH or common Windows locations (Git, etc).
/// Generates root CA on first run, then per-host server certs on the fly.
pub struct ProxyCa {
    ca_cert_pem: String,
    ca_key_path: PathBuf,
    ca_cert_path: PathBuf,
    ca_dir: PathBuf,
    openssl: PathBuf,
    identity_cache: DashMap<String, Arc<Vec<u8>>>,
}

impl ProxyCa {
    /// Find OpenSSL binary: checks PATH first, then common Windows locations
    fn find_openssl() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Try PATH
        if let Ok(out) = Command::new("openssl").arg("version").output() {
            if out.status.success() {
                let ver = String::from_utf8_lossy(&out.stdout);
                println!("[Proxy CA] Found OpenSSL in PATH: {}", ver.trim());
                return Ok(PathBuf::from("openssl"));
            }
        }

        // 2. Common Windows locations
        let candidates = [
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files\Git\clangarm64\bin\openssl.exe",
            r"C:\Program Files\Git\mingw64\bin\openssl.exe",
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
            r"C:\ProgramData\chocolatey\bin\openssl.exe",
            r"C:\msys64\usr\bin\openssl.exe",
            r"C:\Strawberry\c\bin\openssl.exe",
        ];

        for path in &candidates {
            let p = PathBuf::from(path);
            if p.exists() {
                if let Ok(out) = Command::new(&p).arg("version").output() {
                    if out.status.success() {
                        let ver = String::from_utf8_lossy(&out.stdout);
                        println!("[Proxy CA] Found OpenSSL at {}: {}", p.display(), ver.trim());
                        return Ok(p);
                    }
                }
            }
        }

        Err("OpenSSL CLI not found. Install Git for Windows or OpenSSL for HTTPS interception.".into())
    }

    /// Run an openssl command using the discovered binary.
    fn openssl_cmd(&self) -> Command {
        Command::new(&self.openssl)
    }

    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let openssl = Self::find_openssl()?;

        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let ca_dir = PathBuf::from(&home).join(".wondersuite").join("ca");
        fs::create_dir_all(&ca_dir)?;

        let ca_cert_path = ca_dir.join("wondersuite-ca.pem");
        let ca_key_path = ca_dir.join("wondersuite-ca-key.pem");

        if !ca_cert_path.exists() || !ca_key_path.exists() {
            Self::generate_ca_with(&openssl, &ca_cert_path, &ca_key_path)?;
            println!("[Proxy CA] ✓ Generated new root CA: {}", ca_cert_path.display());
            println!("[Proxy CA] ⚠ Install this certificate as Trusted Root CA in your browser!");
        } else {
            println!("[Proxy CA] ✓ Loaded existing CA: {}", ca_cert_path.display());
        }

        let ca_cert_pem = fs::read_to_string(&ca_cert_path)?;

        Ok(Self {
            ca_cert_pem,
            ca_key_path,
            ca_cert_path,
            ca_dir,
            openssl,
            identity_cache: DashMap::new(),
        })
    }

    fn generate_ca_with(openssl: &PathBuf, cert_path: &PathBuf, key_path: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new(openssl)
            .args([
                "req", "-x509", "-new", "-nodes",
                "-keyout", &key_path.to_string_lossy(),
                "-out", &cert_path.to_string_lossy(),
                "-days", "3650",
                "-subj", "/CN=WonderSuite Proxy CA/O=WonderSuite Security Platform/C=DE",
                "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
            ])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to generate CA: {}", err).into());
        }
        Ok(())
    }

    /// Generate a PKCS12 identity for native-tls for the given hostname.
    pub fn generate_identity(&self, host: &str) -> Result<native_tls::Identity, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(cached) = self.identity_cache.get(host) {
            return Ok(native_tls::Identity::from_pkcs12(cached.as_ref(), "wondersuite")?);
        }

        let host_dir = self.ca_dir.join("hosts");
        fs::create_dir_all(&host_dir)?;

        let safe_name = host.replace([':', '*', '?'], "_");
        let host_key = host_dir.join(format!("{}.key", safe_name));
        let host_csr = host_dir.join(format!("{}.csr", safe_name));
        let host_cert = host_dir.join(format!("{}.pem", safe_name));
        let host_p12 = host_dir.join(format!("{}.p12", safe_name));
        let host_ext = host_dir.join(format!("{}.ext", safe_name));

        // SAN extension file
        let ext_content = format!(
            "authorityKeyIdentifier=keyid,issuer\n\
             basicConstraints=CA:FALSE\n\
             keyUsage=digitalSignature,keyEncipherment\n\
             extendedKeyUsage=serverAuth\n\
             subjectAltName=DNS:{}\n",
            host
        );
        fs::write(&host_ext, &ext_content)?;

        // 1. Generate EC key
        let out = self.openssl_cmd()
            .args(["ecparam", "-genkey", "-name", "prime256v1",
                   "-out", &host_key.to_string_lossy()])
            .output()?;
        if !out.status.success() {
            return Err(format!("Key gen failed: {}", String::from_utf8_lossy(&out.stderr)).into());
        }

        // 2. Generate CSR
        let out = self.openssl_cmd()
            .args(["req", "-new", "-key", &host_key.to_string_lossy(),
                   "-out", &host_csr.to_string_lossy(),
                   "-subj", &format!("/CN={}", host)])
            .output()?;
        if !out.status.success() {
            return Err(format!("CSR gen failed: {}", String::from_utf8_lossy(&out.stderr)).into());
        }

        // 3. Sign with our CA
        let out = self.openssl_cmd()
            .args(["x509", "-req",
                   "-in", &host_csr.to_string_lossy(),
                   "-CA", &self.ca_cert_path.to_string_lossy(),
                   "-CAkey", &self.ca_key_path.to_string_lossy(),
                   "-CAcreateserial",
                   "-out", &host_cert.to_string_lossy(),
                   "-days", "825",
                   "-sha256",
                   "-extfile", &host_ext.to_string_lossy()])
            .output()?;
        if !out.status.success() {
            return Err(format!("Cert signing failed: {}", String::from_utf8_lossy(&out.stderr)).into());
        }

        // 4. Export to PKCS12
        let out = self.openssl_cmd()
            .args(["pkcs12", "-export",
                   "-out", &host_p12.to_string_lossy(),
                   "-inkey", &host_key.to_string_lossy(),
                   "-in", &host_cert.to_string_lossy(),
                   "-certfile", &self.ca_cert_path.to_string_lossy(),
                   "-passout", "pass:wondersuite"])
            .output()?;
        if !out.status.success() {
            return Err(format!("PKCS12 export failed: {}", String::from_utf8_lossy(&out.stderr)).into());
        }

        let pkcs12_bytes = fs::read(&host_p12)?;

        // Cleanup temp files
        for f in &[&host_key, &host_csr, &host_cert, &host_ext, &host_p12] {
            let _ = fs::remove_file(f);
        }

        let identity = native_tls::Identity::from_pkcs12(&pkcs12_bytes, "wondersuite")?;
        self.identity_cache.insert(host.to_string(), Arc::new(pkcs12_bytes));

        Ok(identity)
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_cert_path.clone()
    }

    pub fn cache_size(&self) -> usize {
        self.identity_cache.len()
    }
}
