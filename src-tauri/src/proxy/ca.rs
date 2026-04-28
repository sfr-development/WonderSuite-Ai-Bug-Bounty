//! WonderSuite MITM Certificate Authority — Enterprise-Grade, Pure Rust
//!
//! Uses RSA-2048 keys with `x509-cert` for X.509 certificate building and
//! `native-tls` for TLS termination. Zero C/OpenSSL build dependencies.
//!
//! Root cause fix: The old CA used ECDSA P-256 keys, but `native_tls::Identity::from_pkcs8()`
//! on Windows SChannel does NOT support ECDSA PKCS#8. RSA PKCS#8 works perfectly.
//!
//! Works on Windows (x64/ARM64), macOS, and Linux.
//!
//! Features:
//! - RSA-2048 CA root certificate generation & persistence
//! - Per-host TLS certificate issuance (CA-signed, SAN, RSA)
//! - Identity caching via DashMap (zero-cost repeated connections)
//! - OS trust store auto-installation

use dashmap::DashMap;
use der::asn1::{Ia5String, Utf8StringRef, PrintableStringRef};
use der::{Encode, EncodePem};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs1v15::SigningKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use spki::SubjectPublicKeyInfoOwned;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// ─── Cached Identity ──────────────────────────────────────────────────────────

struct CachedIdentity {
    /// PKCS#12 (PFX) binary — the ONLY format that works reliably with Windows SChannel.
    /// Identity::from_pkcs8() silently creates broken credentials (SEC_E_NO_CREDENTIALS).
    pfx_data: Vec<u8>,
}

// ─── Public Struct ────────────────────────────────────────────────────────────

/// WonderSuite CA — 100% Pure Rust, zero C/OpenSSL build deps.
/// Uses RSA-2048 for maximum compatibility with native TLS stacks.
pub struct ProxyCa {
    ca_cert_pem: String,
    #[allow(dead_code)]
    ca_key_pem: String,
    #[allow(dead_code)]
    ca_cert_der: Vec<u8>,
    ca_key: RsaPrivateKey,
    ca_cert_path: PathBuf,
    /// Per-hostname identity cache
    identity_cache: DashMap<String, Arc<CachedIdentity>>,
}

impl ProxyCa {
    /// Initialize the CA. Loads from disk if available, generates new if needed.
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        let ca_dir = PathBuf::from(&home).join(".wondersuite").join("ca");
        fs::create_dir_all(&ca_dir)?;

        let ca_cert_path = ca_dir.join("wondersuite-ca.pem");
        let ca_key_path = ca_dir.join("wondersuite-ca-key.pem");

        let (ca_cert_pem, ca_key_pem, ca_cert_der, ca_key) =
            if ca_cert_path.exists() && ca_key_path.exists() {
                match Self::load_existing(&ca_cert_path, &ca_key_path) {
                    Ok(result) => {
                        println!("[CA] ✓ Loaded existing CA: {}", ca_cert_path.display());
                        result
                    }
                    Err(e) => {
                        println!("[CA] Existing CA invalid ({}), regenerating...", e);
                        let result = Self::generate_and_save(&ca_cert_path, &ca_key_path)?;
                        println!("[CA] ✓ Regenerated root CA: {}", ca_cert_path.display());
                        result
                    }
                }
            } else {
                let result = Self::generate_and_save(&ca_cert_path, &ca_key_path)?;
                println!(
                    "[CA] ✓ Generated new root CA (RSA-2048, pure Rust): {}",
                    ca_cert_path.display()
                );
                result
            };

        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            ca_cert_der,
            ca_key,
            ca_cert_path,
            identity_cache: DashMap::new(),
        })
    }

    /// Load existing CA from PEM files.
    fn load_existing(
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<(String, String, Vec<u8>, RsaPrivateKey), Box<dyn std::error::Error + Send + Sync>>
    {
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;

        if !cert_pem.contains("BEGIN CERTIFICATE") || !key_pem.contains("PRIVATE KEY") {
            return Err("Invalid PEM format".into());
        }

        // Parse the private key
        let key = RsaPrivateKey::from_pkcs8_pem(&key_pem)
            .map_err(|e| format!("Failed to parse CA key: {}", e))?;

        // Extract DER from cert PEM
        let cert_der = pem_to_der(&cert_pem)?;

        Ok((cert_pem, key_pem, cert_der, key))
    }

    /// Generate a new CA and save to disk.
    fn generate_and_save(
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<(String, String, Vec<u8>, RsaPrivateKey), Box<dyn std::error::Error + Send + Sync>>
    {
        let (cert_pem, key_pem, cert_der, key) = Self::generate_ca()?;

        fs::write(cert_path, &cert_pem)?;
        fs::write(key_path, &key_pem)?;

        Ok((cert_pem, key_pem, cert_der, key))
    }

    /// Generate a new RSA-2048 CA root certificate.
    fn generate_ca() -> Result<(String, String, Vec<u8>, RsaPrivateKey), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut rng = rand::thread_rng();
        let ca_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| format!("RSA key generation failed: {}", e))?;

        let ca_pub = RsaPublicKey::from(&ca_key);
        let ca_spki = SubjectPublicKeyInfoOwned::from_key(ca_pub)
            .map_err(|e| format!("SPKI encoding failed: {}", e))?;

        // Build the CA certificate using x509-cert builder
        let serial = SerialNumber::from(1u64);
        let validity = Validity::from_now(std::time::Duration::from_secs(3650 * 86400))
            .map_err(|e| format!("Validity creation failed: {}", e))?;
        let subject = Name::from_str("C=DE,O=WonderSuite,CN=WonderSuite Proxy CA")
            .map_err(|e| format!("Subject name failed: {}", e))?;

        let signer = SigningKey::<Sha256>::new(ca_key.clone());

        let builder = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject,
            ca_spki,
            &signer,
        )
        .map_err(|e| format!("Certificate builder failed: {}", e))?;

        let cert = builder.build()
            .map_err(|e| format!("Certificate build failed: {}", e))?;

        let cert_pem = cert.to_pem(der::pem::LineEnding::LF)
            .map_err(|e| format!("PEM encoding failed: {}", e))?;
        let cert_der = cert.to_der()
            .map_err(|e| format!("DER encoding failed: {}", e))?;
        let key_pem = ca_key.to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| format!("Key PEM encoding failed: {}", e))?
            .to_string();

        Ok((cert_pem, key_pem, cert_der, ca_key))
    }

    // ─── Certificate Issuance ─────────────────────────────────────────────────

    /// Generate a TLS identity (cert + key) for the given hostname.
    /// Returns `native_tls::Identity` ready for use with `TlsAcceptor`.
    ///
    /// Uses PKCS#12 (PFX) format internally because `Identity::from_pkcs8()` on
    /// Windows SChannel silently creates broken credentials (SEC_E_NO_CREDENTIALS).
    pub fn generate_identity(
        &self,
        host: &str,
    ) -> Result<native_tls::Identity, Box<dyn std::error::Error + Send + Sync>> {
        // Check cache first
        if let Some(cached) = self.identity_cache.get(host) {
            return Self::make_identity_from_pkcs12(&cached.pfx_data);
        }

        // Generate new cert for this host → returns PKCS#12 bytes
        let pfx_data = self.issue_host_cert(host)?;

        // Build identity and cache the PFX
        let identity = Self::make_identity_from_pkcs12(&pfx_data)?;
        self.identity_cache.insert(
            host.to_string(),
            Arc::new(CachedIdentity { pfx_data }),
        );

        Ok(identity)
    }

    /// Issue a host certificate signed by this CA.
    /// Returns PKCS#12 (PFX) binary data ready for `Identity::from_pkcs12()`.
    fn issue_host_cert(
        &self,
        host: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut rng = rand::thread_rng();
        let host_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| format!("Host key generation failed: {}", e))?;

        let host_pub = RsaPublicKey::from(&host_key);
        let host_spki = SubjectPublicKeyInfoOwned::from_key(host_pub)
            .map_err(|e| format!("Host SPKI failed: {}", e))?;

        // Random serial
        let serial_bytes: [u8; 16] = rand::random();
        let serial = SerialNumber::new(&serial_bytes)
            .map_err(|e| format!("Serial creation failed: {}", e))?;

        // Validity: 825 days (Apple limit)
        let validity = Validity::from_now(std::time::Duration::from_secs(825 * 86400))
            .map_err(|e| format!("Validity creation failed: {}", e))?;

        // Subject: just the CN
        let subject = Name::from_str(&format!("CN={}", host))
            .map_err(|e| format!("Subject name failed: {}", e))?;

        // Issuer: our CA's DN
        let issuer = Name::from_str("C=DE,O=WonderSuite,CN=WonderSuite Proxy CA")
            .map_err(|e| format!("Issuer name failed: {}", e))?;

        let ca_signer = SigningKey::<Sha256>::new(self.ca_key.clone());

        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer,
                enable_key_agreement: false,
                enable_key_encipherment: true,
            },
            serial,
            validity,
            subject,
            host_spki,
            &ca_signer,
        )
        .map_err(|e| format!("Host cert builder failed: {}", e))?;

        // Add SubjectAltName (DNS name)
        let san = SubjectAltName(vec![
            GeneralName::DnsName(
                Ia5String::new(host)
                    .map_err(|e| format!("Invalid DNS name '{}': {}", host, e))?
            ),
        ]);
        builder.add_extension(&san)
            .map_err(|e| format!("SAN extension failed: {}", e))?;

        let host_cert = builder.build()
            .map_err(|e| format!("Host cert build failed: {}", e))?;

        // Get DER-encoded cert and key
        let host_cert_der = host_cert.to_der()
            .map_err(|e| format!("Host cert DER failed: {}", e))?;
        let ca_cert_der = &self.ca_cert_der;

        let host_key_pkcs8_der = host_key
            .to_pkcs8_der()
            .map_err(|e| format!("Host key DER failed: {}", e))?;

        // Build PKCS#12 (PFX) — the ONLY format that works with Windows SChannel.
        // Identity::from_pkcs8() creates broken credentials on Windows (SEC_E_NO_CREDENTIALS).
        // PFX::new(cert_der, key_der, ca_der_opt, password, name)
        let pfx = p12::PFX::new(
            &host_cert_der,
            host_key_pkcs8_der.as_bytes(),
            Some(ca_cert_der),
            "wondersuite",  // password — Windows SChannel rejects empty passwords
            host,
        ).ok_or_else(|| "PKCS#12 (PFX) generation failed".to_string())?;

        let pfx_der = pfx.to_der();

        Ok(pfx_der)
    }

    /// Create a native_tls::Identity from PKCS#12 (PFX) data.
    /// This is the ONLY reliable method on Windows SChannel.
    fn make_identity_from_pkcs12(
        pfx_data: &[u8],
    ) -> Result<native_tls::Identity, Box<dyn std::error::Error + Send + Sync>> {
        Ok(native_tls::Identity::from_pkcs12(
            pfx_data,
            "wondersuite",  // must match PFX generation password
        )?)
    }

    // ─── OS Trust Store Installation ──────────────────────────────────────────

    /// Auto-install the CA into the OS trust store.
    pub fn install_to_system_trust_store(&self) {
        #[cfg(target_os = "windows")]
        {
            let cert_path = self.ca_cert_path.to_string_lossy().to_string();

            if self.is_already_trusted_windows() {
                println!("[CA] ✓ Root CA already trusted by Windows");
                return;
            }

            // Method 1: certutil.exe -user -addstore (no admin needed for CurrentUser)
            let result = std::process::Command::new("certutil")
                .args(["-user", "-addstore", "-f", "Root", &cert_path])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .output();

            match result {
                Ok(out) if out.status.success() => {
                    println!("[CA] ✓ Root CA installed into Windows CurrentUser trust store");
                    return;
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    eprintln!("[CA] certutil failed: {}", stderr.trim());
                }
                Err(e) => eprintln!("[CA] certutil not found: {}", e),
            }

            // Method 2: PowerShell (fallback)
            let ps_cmd = format!(
                "Import-Certificate -FilePath '{}' -CertStoreLocation Cert:\\CurrentUser\\Root",
                cert_path.replace('"', "\\\"")
            );
            let result = std::process::Command::new("powershell")
                .args(["-NonInteractive", "-NoProfile", "-Command", &ps_cmd])
                .creation_flags(0x08000000)
                .output();

            match result {
                Ok(out) if out.status.success() => {
                    println!("[CA] ✓ Root CA installed via PowerShell");
                }
                _ => {
                    eprintln!("[CA] Manual install: certutil -user -addstore Root {}", cert_path);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let cert_path = self.ca_cert_path.to_string_lossy().to_string();
            let home = std::env::var("HOME").unwrap_or_default();
            let keychain = format!("{}/Library/Keychains/login.keychain-db", home);

            let result = std::process::Command::new("security")
                .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k", &keychain, &cert_path])
                .output();

            match result {
                Ok(out) if out.status.success() => println!("[CA] ✓ Root CA installed on macOS"),
                _ => {
                    let _ = std::process::Command::new("security")
                        .args(["add-trusted-cert", "-d", "-r", "trustRoot",
                               "-k", "/Library/Keychains/System.keychain", &cert_path])
                        .output();
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let cert_path = self.ca_cert_path.to_string_lossy().to_string();
            eprintln!("[CA] Linux: sudo cp {} /usr/local/share/ca-certificates/wondersuite.crt && sudo update-ca-certificates", cert_path);
        }
    }

    #[cfg(target_os = "windows")]
    fn is_already_trusted_windows(&self) -> bool {
        let result = std::process::Command::new("certutil")
            .args(["-user", "-store", "Root", "WonderSuite"])
            .creation_flags(0x08000000)
            .output();
        match result {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains("WonderSuite Proxy CA") || stdout.contains("WonderSuite")
            }
            Err(_) => false,
        }
    }

    // ─── Public Accessors ─────────────────────────────────────────────────────

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

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(STANDARD.decode(b64.trim())?)
}

/// Helper trait for Name parsing
trait FromStr: Sized {
    fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

impl FromStr for Name {
    fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use der::asn1::SetOfVec;
        use x509_cert::attr::AttributeTypeAndValue;
        use x509_cert::name::RelativeDistinguishedName;

        let mut rdns = Vec::new();

        for part in s.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let oid = match key.trim() {
                    "C" | "c" => const_oid::db::rfc4519::C,
                    "O" | "o" => const_oid::db::rfc4519::O,
                    "CN" | "cn" => const_oid::db::rfc4519::CN,
                    "OU" | "ou" => const_oid::db::rfc4519::OU,
                    "L" | "l" => const_oid::db::rfc4519::L,
                    "ST" | "st" => const_oid::db::rfc4519::ST,
                    _ => continue,
                };

                let value = value.trim();
                let attr_value = if key.trim() == "C" || key.trim() == "c" {
                    // Country must be PrintableString
                    der::Any::from(PrintableStringRef::new(value)
                        .map_err(|e| format!("Invalid country '{}': {}", value, e))?)
                } else {
                    // Everything else as UTF8String
                    der::Any::from(Utf8StringRef::new(value)
                        .map_err(|e| format!("Invalid value '{}': {}", value, e))?)
                };

                let atv = AttributeTypeAndValue {
                    oid,
                    value: attr_value,
                };

                let mut set = SetOfVec::new();
                set.insert(atv).map_err(|e| format!("RDN insert failed: {}", e))?;
                rdns.push(RelativeDistinguishedName::from(set));
            }
        }

        Ok(Name::from(rdns))
    }
}
