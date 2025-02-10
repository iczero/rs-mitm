use eyre::Context;
use rcgen::{CertificateParams, KeyPair};
use rs_mitm::certgen::SigningCA;
use rs_mitm::{certgen, common};
use tokio::fs;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    common::initialize_logging();
    info!("Hello, world!");

    let ca = load_or_create_ca().await?;
    Ok(())
}

async fn load_or_create_ca() -> eyre::Result<SigningCA> {
    if let Ok((cert_pem, key_pem)) =
        tokio::try_join!(fs::read("data/ca-cert.pem"), fs::read("data/ca-key.pem"))
    {
        let out =
            certgen::load_ca_pem(&cert_pem, &key_pem).wrap_err("parsing CA certificate/key")?;
        info!("loaded CA certificate");
        Ok(out)
    } else {
        let signing_ca = certgen::make_ca();
        let cert_pem = pem::Pem::new("CERTIFICATE", signing_ca.cert.to_vec());
        let key_pem = pem::Pem::new("PRIVATE KEY", signing_ca.key.secret_der().to_vec());
        tokio::try_join!(
            fs::write("data/ca-cert.pem", pem::encode(&cert_pem)),
            fs::write("data/ca-key.pem", pem::encode(&key_pem)),
        )
        .wrap_err("writing CA certificate")?;
        info!("created CA certificate");
        Ok(signing_ca)
    }
}
