//! SPIFFE SVID Plugin
//!
//! This plugin generates X.509 SVIDs for attested TEE workloads.
//! It maps attestation claims to SPIFFE IDs and issues short-lived
//! certificates signed by a configured CA.

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{
            BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
        },
        X509Builder, X509NameBuilder, X509,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use regex::Regex;

use crate::plugins::plugin_manager::ClientPlugin;

/// Default SVID TTL in seconds (1 hour)
const DEFAULT_SVID_TTL_SECS: u64 = 3600;

/// RSA key size for generated SVIDs
const RSA_KEY_SIZE: u32 = 2048;

// ============================================================================
// Configuration
// ============================================================================

/// SPIFFE Plugin configuration from KBS config file
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SpiffePluginConfig {
    /// SPIFFE trust domain (e.g., "example.org")
    pub trust_domain: String,

    /// Path to CA certificate (PEM)
    pub ca_cert_path: PathBuf,

    /// Path to CA private key (PEM)
    pub ca_key_path: PathBuf,

    /// SVID TTL in seconds (default: 3600)
    pub svid_ttl_secs: Option<u64>,

    /// Working directory for temporary files
    pub work_dir: Option<String>,

    /// Claim-to-SPIFFE-ID mapping rules
    pub id_mapping: Option<SpiffeIdMappingConfig>,
}

/// Configuration for mapping attestation claims to SPIFFE IDs
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SpiffeIdMappingConfig {
    /// Static mappings from specific claim values to SPIFFE paths
    pub static_mappings: Option<Vec<StaticMapping>>,
    /// Template for generating SPIFFE path from claims
    /// Example: "/workload/{{ tee }}/{{ image_digest }}"
    pub path_template: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StaticMapping {
    /// Claim field to match (e.g., "image_digest")
    pub claim_field: String,
    /// Value to match
    pub claim_value: String,
    /// Resulting SPIFFE ID path
    pub spiffe_path: String,
}

// ============================================================================
// Plugin Implementation
// ============================================================================

/// SPIFFE SVID Plugin
pub struct SpiffePlugin {
    /// SPIFFE trust domain
    trust_domain: String,

    /// CA certificate
    ca_cert: X509,

    /// CA private key
    ca_key: PKey<Private>,

    /// CA certificate (PEM bytes for response)
    ca_cert_pem: Vec<u8>,

    /// SVID TTL in seconds
    svid_ttl_secs: u64,

    /// ID mapping config
    id_mapping: Option<SpiffeIdMappingConfig>,
}

impl TryFrom<SpiffePluginConfig> for SpiffePlugin {
    type Error = anyhow::Error;

    fn try_from(config: SpiffePluginConfig) -> Result<Self> {
        // Load CA cert
        let ca_cert_pem = std::fs::read(&config.ca_cert_path)
            .context(format!("Failed to read CA cert: {:?}", config.ca_cert_path))?;
        let ca_cert = X509::from_pem(&ca_cert_pem)
            .context("Failed to parse CA certificate PEM")?;

        // Load CA key
        let ca_key_pem = std::fs::read(&config.ca_key_path)
            .context(format!("Failed to read CA key: {:?}", config.ca_key_path))?;
        let ca_key = PKey::private_key_from_pem(&ca_key_pem)
            .context("Failed to parse CA private key PEM")?;

        let svid_ttl_secs = config.svid_ttl_secs.unwrap_or(DEFAULT_SVID_TTL_SECS);

        log::info!(
            "SPIFFE plugin initialized: trust_domain={}, ttl={}s",
            config.trust_domain,
            svid_ttl_secs
        );

        Ok(Self {
            trust_domain: config.trust_domain,
            ca_cert,
            ca_key,
            ca_cert_pem,
            svid_ttl_secs,
            id_mapping: config.id_mapping,
        })
    }
}

// ============================================================================
// SVID Generation
// ============================================================================

/// Output format for SVID response
/// All certificate/key data is Base64-encoded DER format per SPIFFE spec
#[derive(Serialize, Deserialize)]
pub struct SvidResponse {
    /// SPIFFE ID
    pub spiffe_id: String,
    /// X.509 certificate (Base64-encoded DER)
    pub svid: String,
    /// Private key (Base64-encoded DER PKCS#8)
    pub key: String,
    /// Trust bundle - CA cert (Base64-encoded DER)
    pub bundle: String,
}

impl SpiffePlugin {
    /// Sanitizes a string for use in a SPIFFE ID path component.
    ///
    /// Per RFC 3986, path segments should only contain unreserved characters:
    /// A-Z, a-z, 0-9, hyphen (-), period (.), underscore (_), tilde (~)
    ///
    /// Any other characters are replaced with hyphens. Multiple consecutive
    /// hyphens are collapsed to a single hyphen.
    fn sanitize_for_spiffe_path(value: &str) -> String {
        let sanitized: String = value
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~' {
                    c
                } else {
                    '-'
                }
            })
            .collect();

        // Collapse multiple consecutive hyphens
        let mut result = String::with_capacity(sanitized.len());
        let mut prev_hyphen = false;
        for c in sanitized.chars() {
            if c == '-' {
                if !prev_hyphen {
                    result.push(c);
                }
                prev_hyphen = true;
            } else {
                result.push(c);
                prev_hyphen = false;
            }
        }

        // Trim leading/trailing hyphens
        result.trim_matches('-').to_string()
    }

    /// Generate SPIFFE ID from attestation claims
    fn claims_to_spiffe_id(&self, claims: &Value) -> Result<String> {
        // Check for static mappings first
        if let Some(ref mapping_config) = self.id_mapping {
            if let Some(ref static_mappings) = mapping_config.static_mappings {
                for mapping in static_mappings {
                    if let Some(claim_value) = claims.get(&mapping.claim_field).and_then(|v| v.as_str()) {
                        if claim_value == mapping.claim_value {
                            return Ok(format!(
                                "spiffe://{}{}",
                                self.trust_domain, mapping.spiffe_path
                            ));
                        }
                    }
                }
            }

            // Template-based mapping: replace {{ claim_name }} with claim values
            if let Some(ref template) = mapping_config.path_template {
                let path = self.render_template(template, claims)?;
                return Ok(format!("spiffe://{}{}", self.trust_domain, path));
            }
        }

        // Default mappings based on common claim patterns

        // 1. Kubernetes-style: namespace/serviceaccount
        if let (Some(ns), Some(sa)) = (
            claims.get("namespace").and_then(|v| v.as_str()),
            claims.get("serviceaccount").and_then(|v| v.as_str()),
        ) {
            return Ok(format!(
                "spiffe://{}/ns/{}/sa/{}",
                self.trust_domain, ns, sa
            ));
        }

        // 2. Image digest based
        if let Some(digest) = claims.get("image_digest").and_then(|v| v.as_str()) {
            let safe_digest = digest.replace(':', "-");
            return Ok(format!(
                "spiffe://{}/workload/{}",
                self.trust_domain, safe_digest
            ));
        }

        // 3. TEE measurement based
        if let Some(measurement) = claims.get("measurement").and_then(|v| v.as_str()) {
            return Ok(format!(
                "spiffe://{}/tee/{}",
                self.trust_domain, measurement
            ));
        }

        // 4. TEE type fallback
        if let Some(tee) = claims.get("tee").and_then(|v| v.as_str()) {
            return Ok(format!(
                "spiffe://{}/tee-type/{}",
                self.trust_domain, tee
            ));
        }

        Err(anyhow!("Unable to derive SPIFFE ID from attestation claims"))
    }

    /// Render a template string by replacing {{ claim_name }} with claim values
    fn render_template(&self, template: &str, claims: &Value) -> Result<String> {
        let mut result = template.to_string();

        // Find all {{ ... }} patterns
        let re = Regex::new(r"\{\{\s*(\w+)\s*\}\}")
            .map_err(|e| anyhow!("Invalid template regex: {}", e))?;

        for cap in re.captures_iter(template) {
            let full_match = &cap[0];      // e.g., "{{ namespace }}"
            let claim_name = &cap[1];       // e.g., "namespace"

            let claim_value_str = claims
                .get(claim_name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Template references missing claim: {}", claim_name))?;

            // Sanitize the value for use in SPIFFE ID path
            let sanitized_claim_value = Self::sanitize_for_spiffe_path(&claim_value_str);

            result = result.replace(full_match, &sanitized_claim_value);
        }

        Ok(result)
    }

    /// Generate X.509 SVID for the given SPIFFE ID
    async fn generate_x509_svid(&self, spiffe_id: &str) -> Result<SvidResponse> {
        log::info!("Generating X.509 SVID for: {}", spiffe_id);

        // 1. Generate keypair for the SVID
        // RSA key generation is CPU-intensive; offload to blocking thread pool
        // to avoid blocking the async executor
        let rsa = tokio::task::spawn_blocking(|| {
            Rsa::generate(RSA_KEY_SIZE)
        })
        .await
        .context("Key generation task failed")?
        .context("Failed to generate RSA keypair")?;
        
        let svid_key = PKey::from_rsa(rsa)
            .context("Failed to create PKey from RSA")?;

        // 2. Build the X.509 certificate
        let mut builder = X509Builder::new()
            .context("Failed to create X509Builder")?;

        // Version 3 (0-indexed, so 2)
        builder.set_version(2)
            .context("Failed to set certificate version")?;

        // Serial number (random)
        let serial = {
            let mut bn = BigNum::new().context("Failed to create BigNum")?;
            bn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
                .context("Failed to generate random serial")?;
            bn.to_asn1_integer().context("Failed to convert to ASN1")?
        };
        builder.set_serial_number(&serial)
            .context("Failed to set serial number")?;

        // Validity period
        let not_before = Asn1Time::from_unix(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("System time is before UNIX_EPOCH")?
                .as_secs() as i64
        ).context("Failed to create not_before time")?;
        
        let not_after = Asn1Time::from_unix(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("System time is before UNIX_EPOCH")?
                .as_secs() as i64 + self.svid_ttl_secs as i64
        ).context("Failed to create not_after time")?;

        builder.set_not_before(&not_before)
            .context("Failed to set not_before")?;
        builder.set_not_after(&not_after)
            .context("Failed to set not_after")?;

        // Subject (CN = SPIFFE ID)
        let mut subject_name = X509NameBuilder::new()
            .context("Failed to create X509NameBuilder")?;
        subject_name.append_entry_by_text("CN", spiffe_id)
            .context("Failed to set CN")?;
        let subject_name = subject_name.build();
        builder.set_subject_name(&subject_name)
            .context("Failed to set subject name")?;

        // Issuer (from CA cert)
        builder.set_issuer_name(self.ca_cert.subject_name())
            .context("Failed to set issuer name")?;

        // Public key
        builder.set_pubkey(&svid_key)
            .context("Failed to set public key")?;

        // Extensions
        // Basic constraints: CA=false
        let basic_constraints = BasicConstraints::new()
            .critical()
            .build()
            .context("Failed to build basic constraints")?;
        builder.append_extension(basic_constraints)
            .context("Failed to append basic constraints")?;

        // Key usage: digitalSignature, keyEncipherment
        let key_usage = KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .context("Failed to build key usage")?;
        builder.append_extension(key_usage)
            .context("Failed to append key usage")?;

        // Extended key usage: serverAuth, clientAuth
        let ext_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()
            .context("Failed to build extended key usage")?;
        builder.append_extension(ext_key_usage)
            .context("Failed to append extended key usage")?;

        // Subject Alternative Name: URI = SPIFFE ID
        let ctx = builder.x509v3_context(Some(&self.ca_cert), None);
        let san = SubjectAlternativeName::new()
            .critical()
            .uri(spiffe_id)
            .build(&ctx)
            .context("Failed to build SAN")?;
        builder.append_extension(san)
            .context("Failed to append SAN")?;

        // 3. Sign with CA key
        builder.sign(&self.ca_key, MessageDigest::sha256())
            .context("Failed to sign certificate")?;

        let cert = builder.build();

        // 4. Convert to Base64-encoded DER (SPIFFE spec format)
        let svid_der = cert.to_der()
            .context("Failed to convert cert to DER")?;
        let key_der = svid_key.private_key_to_der()
            .context("Failed to convert key to DER")?;
        let bundle_der = self.ca_cert.to_der()
            .context("Failed to convert CA cert to DER")?;

        log::info!("Successfully generated SVID for: {}", spiffe_id);

        Ok(SvidResponse {
            spiffe_id: spiffe_id.to_string(),
            svid: BASE64.encode(&svid_der),
            key: BASE64.encode(&key_der),
            bundle: BASE64.encode(&bundle_der),
        })
    }
}

// ============================================================================
// ClientPlugin Trait Implementation
// ============================================================================

#[async_trait::async_trait]
impl ClientPlugin for SpiffePlugin {
    async fn handle(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
        claims: Option<&Value>,
    ) -> Result<Vec<u8>> {
        // Only support GET requests
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method. Only GET is supported");
        }

        let sub_path = path
            .strip_prefix('/')
            .context("Path should start with `/`")?;

        match sub_path {
            // GET /kbs/v0/spiffe/svid/x509
            "svid/x509" => {
                let claims = claims.ok_or_else(|| {
                    anyhow!("Attestation claims required for SVID issuance")
                })?;

                // Map claims to SPIFFE ID
                let spiffe_id = self.claims_to_spiffe_id(claims)?;

                // Generate SVID
                let svid_response = self.generate_x509_svid(&spiffe_id).await?;

                // Serialize response
                let response_json = serde_json::to_vec(&svid_response)
                    .context("Failed to serialize SVID response")?;

                Ok(response_json)
            }

            // GET /kbs/v0/spiffe/bundle
            "bundle" => {
                // Return just the trust bundle
                let bundle_response = serde_json::json!({
                    "bundle": String::from_utf8_lossy(&self.ca_cert_pem).to_string()
                });

                let response_json = serde_json::to_vec(&bundle_response)
                    .context("Failed to serialize bundle response")?;

                Ok(response_json)
            }

            _ => bail!("Unknown SPIFFE endpoint: {}. Valid: svid/x509, bundle", sub_path),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        _method: &Method,
    ) -> Result<bool> {
        // Returns:
        //   true  = Admin auth is sufficient (no TEE attestation required)
        //   false = TEE attestation required (claims must be present)

        let sub_path = path.strip_prefix('/').unwrap_or(path);

        match sub_path {
            // GET /kbs/v0/spiffe/bundle
            // Returns CA cert (trust bundle) - public info for verifying peer SVIDs
            // Safe to serve without attestation
            "bundle" => Ok(true),

            // GET /kbs/v0/spiffe/svid/x509 (and any other endpoints)
            // Returns private key material - requires TEE attestation
            _ => Ok(false),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        _method: &Method,
    ) -> Result<bool> {
        // DEVELOPMENT MODE: Disable encryption for trusted network environments
        // WARNING: This returns private key material unencrypted!
        // In production, enable encryption and implement JWE decryption in the client
        Ok(false)
        
        // PRODUCTION MODE (commented out):
        // Only endpoints returning private key material need encryption.
        // The /bundle endpoint returns only the public CA cert.
        // let sub_path = path.strip_prefix('/').unwrap_or(path);
        // match sub_path {
        //     "bundle" => Ok(false),
        //     _ => Ok(true),
        // }
    }
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::x509::X509;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::asn1::Asn1Time;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::hash::MessageDigest;
    use openssl::x509::{X509Builder, X509NameBuilder};

    /// Generate a test CA cert and key
    fn create_test_ca() -> (X509, PKey<openssl::pkey::Private>, Vec<u8>) {
        let rsa = Rsa::generate(2048).unwrap();
        let ca_key = PKey::from_rsa(rsa).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test CA").unwrap();
        let name = name_builder.build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();

        builder.set_pubkey(&ca_key).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
        builder.append_extension(basic_constraints).unwrap();

        let key_usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap();
        builder.append_extension(key_usage).unwrap();

        builder.sign(&ca_key, MessageDigest::sha256()).unwrap();

        let ca_cert = builder.build();
        let ca_cert_pem = ca_cert.to_pem().unwrap();

        (ca_cert, ca_key, ca_cert_pem)
    }

    /// Create a SpiffePlugin with test CA
    fn create_test_plugin() -> SpiffePlugin {
        let (ca_cert, ca_key, ca_cert_pem) = create_test_ca();

        SpiffePlugin {
            trust_domain: "example.org".to_string(),
            ca_cert,
            ca_key,
            ca_cert_pem,
            svid_ttl_secs: 3600,
            id_mapping: None,
        }
    }

    #[tokio::test]
    async fn test_generate_x509_svid() {
        let plugin = create_test_plugin();
        let spiffe_id = "spiffe://example.org/workload/test";

        let result = plugin.generate_x509_svid(spiffe_id).await;
        assert!(result.is_ok(), "SVID generation failed: {:?}", result.err());
        let svid_response = result.unwrap();

        // Verify SPIFFE ID is returned
        assert_eq!(svid_response.spiffe_id, spiffe_id);

        // Verify cert is valid DER (Base64 decode then parse)
        let cert_der = BASE64.decode(&svid_response.svid)
            .expect("Failed to decode Base64 cert");
        let cert = X509::from_der(&cert_der)
            .expect("Invalid certificate DER");

        // Verify key is valid DER
        let key_der = BASE64.decode(&svid_response.key)
            .expect("Failed to decode Base64 key");
        let _key = PKey::private_key_from_der(&key_der)
            .expect("Invalid private key DER");

        // Verify bundle is valid DER
        let bundle_der = BASE64.decode(&svid_response.bundle)
            .expect("Failed to decode Base64 bundle");
        let _bundle = X509::from_der(&bundle_der)
            .expect("Invalid bundle DER");

        // Verify SPIFFE ID is in the SAN
        let san = cert.subject_alt_names();
        assert!(san.is_some(), "No SAN extension found");
        
        let san = san.unwrap();
        let mut found_spiffe_id = false;
        for name in san.iter() {
            if let Some(uri) = name.uri() {
                if uri == spiffe_id {
                    found_spiffe_id = true;
                    break;
                }
            }
        }
        assert!(found_spiffe_id, "SPIFFE ID not found in SAN URI");
    }

    #[tokio::test]
    async fn test_generate_svid_cert_is_signed_by_ca() {
        let plugin = create_test_plugin();
        let spiffe_id = "spiffe://example.org/workload/test";

        let svid_response = plugin.generate_x509_svid(spiffe_id).await.unwrap();
        
        let cert_der = BASE64.decode(&svid_response.svid).unwrap();
        let cert = X509::from_der(&cert_der).unwrap();
        
        let bundle_der = BASE64.decode(&svid_response.bundle).unwrap();
        let ca_cert = X509::from_der(&bundle_der).unwrap();

        // Verify the cert is signed by the CA
        let ca_pubkey = ca_cert.public_key().unwrap();
        assert!(cert.verify(&ca_pubkey).unwrap(), "Certificate not signed by CA");
    }

    #[tokio::test]
    async fn test_generate_svid_key_matches_cert() {
        let plugin = create_test_plugin();
        let spiffe_id = "spiffe://example.org/workload/test";

        let svid_response = plugin.generate_x509_svid(spiffe_id).await.unwrap();
        
        let cert_der = BASE64.decode(&svid_response.svid).unwrap();
        let cert = X509::from_der(&cert_der).unwrap();
        
        let key_der = BASE64.decode(&svid_response.key).unwrap();
        let key = PKey::private_key_from_der(&key_der).unwrap();

        // Verify public key in cert matches the private key
        let cert_pubkey = cert.public_key().unwrap();
        assert!(cert_pubkey.public_eq(&key), "Key does not match certificate");
    }

    #[test]
    fn test_claims_to_spiffe_id_with_namespace_sa() {
        let plugin = create_test_plugin();
        
        let claims = serde_json::json!({
            "namespace": "default",
            "serviceaccount": "my-service"
        });

        let result = plugin.claims_to_spiffe_id(&claims);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "spiffe://example.org/ns/default/sa/my-service"
        );
    }

    #[test]
    fn test_claims_to_spiffe_id_with_image_digest() {
        let plugin = create_test_plugin();
        
        let claims = serde_json::json!({
            "image_digest": "sha256:abc123"
        });

        let result = plugin.claims_to_spiffe_id(&claims);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "spiffe://example.org/workload/sha256-abc123"
        );
    }

    #[test]
    fn test_claims_to_spiffe_id_with_tee_type() {
        let plugin = create_test_plugin();
        
        let claims = serde_json::json!({
            "tee": "sev-snp"
        });

        let result = plugin.claims_to_spiffe_id(&claims);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "spiffe://example.org/tee-type/sev-snp"
        );
    }

    #[test]
    fn test_claims_to_spiffe_id_no_suitable_claims() {
        let plugin = create_test_plugin();
        
        let claims = serde_json::json!({
            "random_field": "random_value"
        });

        let result = plugin.claims_to_spiffe_id(&claims);
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_to_spiffe_id_with_template() {
        let (ca_cert, ca_key, ca_cert_pem) = create_test_ca();

        let plugin = SpiffePlugin {
            trust_domain: "example.org".to_string(),
            ca_cert,
            ca_key,
            ca_cert_pem,
            svid_ttl_secs: 3600,
            id_mapping: Some(SpiffeIdMappingConfig {
                static_mappings: None,
                path_template: Some("/workload/{{ tee }}/{{ namespace }}".to_string()),
            }),
        };

        let claims = serde_json::json!({
            "tee": "sev-snp",
            "namespace": "production"
        });

        let result = plugin.claims_to_spiffe_id(&claims);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "spiffe://example.org/workload/sev-snp/production"
        );
    }

    #[test]
    fn test_claims_to_spiffe_id_template_missing_claim() {
        let (ca_cert, ca_key, ca_cert_pem) = create_test_ca();

        let plugin = SpiffePlugin {
            trust_domain: "example.org".to_string(),
            ca_cert,
            ca_key,
            ca_cert_pem,
            svid_ttl_secs: 3600,
            id_mapping: Some(SpiffeIdMappingConfig {
                static_mappings: None,
                path_template: Some("/workload/{{ missing_claim }}".to_string()),
            }),
        };

        let claims = serde_json::json!({
            "tee": "sev-snp"
        });

        let result = plugin.claims_to_spiffe_id(&claims);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_svid_endpoint() {
        let plugin = create_test_plugin();

        let claims = serde_json::json!({
            "tee": "sev-snp",
            "namespace": "production",
            "serviceaccount": "my-service"
        });

        let result = plugin
            .handle(
                &[],                          // body
                "",                           // query
                "/svid/x509",                 // path
                &Method::GET,                 // method
                Some(&claims),                // claims (mocked!)
            )
            .await;

        assert!(result.is_ok(), "Handle failed: {:?}", result.err());

        let response: SvidResponse = serde_json::from_slice(&result.unwrap()).unwrap();

        assert_eq!(response.spiffe_id, "spiffe://example.org/ns/production/sa/my-service");

        // Verify svid is valid Base64-encoded DER (not PEM)
        let svid_der = BASE64.decode(&response.svid)
            .expect("svid should be valid Base64");
        let _cert = X509::from_der(&svid_der)
            .expect("svid should be valid DER certificate");

        // Verify key is valid Base64-encoded DER
        let key_der = BASE64.decode(&response.key)
            .expect("key should be valid Base64");
        let _key = PKey::private_key_from_der(&key_der)
            .expect("key should be valid DER private key");

        // Verify bundle is valid Base64-encoded DER
        let bundle_der = BASE64.decode(&response.bundle)
            .expect("bundle should be valid Base64");
        let _ca = X509::from_der(&bundle_der)
            .expect("bundle should be valid DER certificate");
    }

    #[tokio::test]
    async fn test_handle_bundle_endpoint() {
        let plugin = create_test_plugin();

        let result = plugin
            .handle(
                &[],
                "",
                "/bundle",
                &Method::GET,
                None,  // No claims needed for bundle
            )
            .await;

        assert!(result.is_ok());

        let response: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert!(response["bundle"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_handle_svid_without_claims_fails() {
        let plugin = create_test_plugin();

        let result = plugin
            .handle(
                &[],
                "",
                "/svid/x509",
                &Method::GET,
                None,  // No claims - should fail!
            )
            .await;

        assert!(result.is_err());
    }
}