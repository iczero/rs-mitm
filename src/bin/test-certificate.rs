use eyre::Context;
use rs_mitm::ca::SigningCA;
use rs_mitm::common;
use tokio::fs;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    common::initialize_logging();
    info!("Hello, world!");

    let ca = load_or_create_ca().await?;
    let pair = ca.create_cert_for_names(vec![rcgen::SanType::DnsName(
        std::env::args()
            .nth(1)
            .expect("no arg")
            .try_into()
            .expect("bad name"),
    )]);
    fs::write(
        "data/test-cert.pem",
        pem_encode("CERTIFICATE", pair.certificate_chain[0].to_vec()),
    )
    .await?;
    fs::write(
        "data/test-key.pem",
        pem_encode("PRIVATE KEY", pair.key.secret_der().to_vec()),
    )
    .await?;
    Ok(())
}

fn pem_encode(tag: impl ToString, contents: Vec<u8>) -> String {
    pem::encode(&pem::Pem::new(tag, contents))
}

async fn load_or_create_ca() -> eyre::Result<SigningCA> {
    if let Ok((cert_pem, key_pem)) =
        tokio::try_join!(fs::read("data/ca-cert.pem"), fs::read("data/ca-key.pem"))
    {
        let out =
            SigningCA::load_ca_pem(&cert_pem, &key_pem).wrap_err("parsing CA certificate/key")?;
        info!("loaded CA certificate");
        Ok(out)
    } else {
        let signing_ca = SigningCA::make_ca();
        tokio::try_join!(
            fs::write(
                "data/ca-cert.pem",
                pem_encode("CERTIFICATE", signing_ca.cert.to_vec())
            ),
            fs::write(
                "data/ca-key.pem",
                pem_encode("PRIVATE KEY", signing_ca.key.secret_der().to_vec())
            ),
        )
        .wrap_err("writing CA certificate")?;
        info!("created CA certificate");
        Ok(signing_ca)
    }
}
