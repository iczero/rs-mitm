use eyre::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, KeyPair, KeyUsagePurpose};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};

pub fn make_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 3);
    params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
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

    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("failed to generate ECC P-256 keypair");
    let certificate = params
        .self_signed(&keypair)
        .expect("failed to sign certificate");
    (certificate, keypair)
}

pub fn load_ca_pem(cert_pem: &[u8], key_pem: &[u8]) -> eyre::Result<(CertificateParams, KeyPair)> {
    let cert_der =
        CertificateDer::from_pem_slice(cert_pem).wrap_err("failed to parse CA certificate file")?;
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
    let cert_params =
        CertificateParams::from_ca_cert_der(&cert_der).wrap_err("failed to load CA certificate")?;
    let key_der = PrivateKeyDer::from_pem_slice(key_pem).wrap_err("failed to parse CA key file")?;
    let keypair =
        KeyPair::from_der_and_sign_algo(&key_der, sig_alg).wrap_err("failed to load CA key")?;
    Ok((cert_params, keypair))
}
