use eyre::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime, Time};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Represents a CA capable of signing certificates
pub struct SigningCA {
    /// CA certificate
    pub cert: CertificateDer<'static>,
    /// CA private key
    pub key: PrivateKeyDer<'static>,
    /// `rcgen` certificate parameters used for signing
    pub ca_signing_params: CertificateParams,
    /// `rcgen` keypair used for signing
    pub ca_signing_key: KeyPair,
}

/// Certificate with key
pub struct CertificateWithKey {
    /// Certificate chain, with end-entity certificate first
    pub certificate_chain: Vec<CertificateDer<'static>>,
    /// Private key
    pub key: PrivateKeyDer<'static>,
}

impl SigningCA {
    pub fn make_ca() -> Self {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.not_before = OffsetDateTime::now_utc().replace_time(Time::MIDNIGHT);
        params.not_after = params.not_before + Duration::days(365 * 3); // 3 years
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.extend_from_slice(&[
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ]);
        let dn = &mut params.distinguished_name;
        dn.push(DnType::CountryName, "US");
        dn.push(DnType::OrganizationName, "Mouse Widgits LLC");
        dn.push(DnType::OrganizationalUnitName, "Network Services");
        dn.push(DnType::CommonName, "Decryption CA");

        let keypair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("failed to generate ECC P-256 keypair");
        let certificate = params
            .self_signed(&keypair)
            .expect("failed to sign certificate");

        SigningCA {
            cert: certificate.der().clone(),
            key: PrivateKeyDer::try_from(keypair.serialized_der())
                .unwrap()
                .clone_key(),
            ca_signing_params: certificate.params().clone(),
            ca_signing_key: keypair,
        }
    }

    pub fn load_ca_pem(cert_pem: &[u8], key_pem: &[u8]) -> eyre::Result<Self> {
        let cert_der = CertificateDer::from_pem_slice(cert_pem)
            .wrap_err("failed to parse CA certificate file")?
            .into_owned();
        let (_, cert_parsed) =
            X509Certificate::from_der(&cert_der).wrap_err("failed to parse CA certificate file")?;
        let sig_alg_oid: Vec<u64> = cert_parsed
            .signature_algorithm
            .oid()
            .iter()
            .expect("unexpectedly large OID")
            .collect();
        let sig_alg =
            rcgen::SignatureAlgorithm::from_oid(&sig_alg_oid).wrap_err("unknown signature type")?;
        let cert_params = CertificateParams::from_ca_cert_der(&cert_der)
            .wrap_err("failed to load CA certificate")?;
        let key_der = PrivateKeyDer::from_pem_slice(key_pem)
            .wrap_err("failed to parse CA key file")?
            .clone_key();
        let keypair =
            KeyPair::from_der_and_sign_algo(&key_der, sig_alg).wrap_err("failed to load CA key")?;

        Ok(SigningCA {
            cert: cert_der,
            key: key_der,
            ca_signing_params: cert_params,
            ca_signing_key: keypair,
        })
    }

    pub fn sign_certificate(
        &self,
        params: CertificateParams,
        key: KeyPair,
    ) -> Result<CertificateWithKey, rcgen::Error> {
        let cert = params.signed_by(&key, &self.ca_signing_params, &self.ca_signing_key)?;
        Ok(CertificateWithKey {
            certificate_chain: vec![cert.into(), self.cert.clone()],
            key: PrivateKeyDer::try_from(key.serialize_der()).expect("invalid key"),
        })
    }

    /// Create a temporary 30-day certificate for hostname
    pub fn create_cert_for_names(&self, names: Vec<SanType>) -> CertificateWithKey {
        let mut params = CertificateParams::new(vec![]).unwrap();
        let common_name: &str = match &names[0] {
            SanType::Rfc822Name(str) | SanType::DnsName(str) | SanType::URI(str) => str.as_str(),
            SanType::IpAddress(addr) => &addr.to_string(),
            SanType::OtherName((_, rcgen::OtherNameValue::Utf8String(str))) => str,
            _ => panic!("unknown or unsupported SAN type"),
        };
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.subject_alt_names = names;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.extend_from_slice(&[
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ]);
        params.not_before = OffsetDateTime::now_utc().replace_time(Time::MIDNIGHT);
        params.not_after = params.not_before + Duration::days(30);

        let keypair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("failed to generate ECC P-256 keypair");
        self.sign_certificate(params, keypair)
            .expect("failed to sign certificate")
    }
}

impl CertificateWithKey {
    pub fn into_certified_key(self, crypto_provider: &CryptoProvider) -> CertifiedKey {
        CertifiedKey::new(
            self.certificate_chain,
            crypto_provider
                .key_provider
                .load_private_key(self.key)
                .expect("invalid private key"),
        )
    }
}
