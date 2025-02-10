use eyre::Context;
use rcgen::{CertificateParams, KeyPair};
use rs_mitm::{certgen, common};
use tokio::fs;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    common::initialize_logging();
    info!("Hello, world!");

    let (ca_cert_params, ca_key) = load_or_create_ca().await?;
    Ok(())
}

async fn load_or_create_ca() -> eyre::Result<(CertificateParams, KeyPair)> {
    if let Ok((cert_pem, key_pem)) =
        tokio::try_join!(fs::read("data/ca-cert.pem"), fs::read("data/ca-key.pem"))
    {
        let out =
            certgen::load_ca_pem(&cert_pem, &key_pem).wrap_err("parsing CA certificate/key")?;
        info!("loaded CA certificate");
        Ok(out)
    } else {
        info!("creating CA certificate");
        let (ca_cert, ca_key) = certgen::make_ca();
        tokio::try_join!(
            fs::write("data/ca-cert.pem", ca_cert.pem()),
            fs::write("data/ca-key.pem", ca_key.serialize_pem()),
        )
        .wrap_err("writing CA certificate")?;
        Ok((ca_cert.params().clone(), ca_key))
    }
}
