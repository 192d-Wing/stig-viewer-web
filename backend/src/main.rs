use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    stig_viewer_backend::run().await
}
