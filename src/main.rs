//! Entrypoint: environment-driven configuration, then serve the whole
//! estate forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    unidpp_server::run().await
}
