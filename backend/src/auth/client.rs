//! OIDC client: discovery + construction.

use anyhow::{Context, Result};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};

use super::OidcConfig;

/// Perform OIDC discovery and build the relying-party client.
///
/// The caller is expected to have already checked [`OidcConfig::is_enabled`];
/// this function unwraps the required fields with explicit errors.
pub async fn build(cfg: &OidcConfig) -> Result<CoreClient> {
    let issuer = cfg
        .issuer_url
        .as_deref()
        .context("OIDC_ISSUER_URL is required")?;
    let client_id = cfg
        .client_id
        .as_deref()
        .context("OIDC_CLIENT_ID is required")?;
    let client_secret = cfg
        .client_secret
        .as_deref()
        .context("OIDC_CLIENT_SECRET is required")?;
    let redirect_uri = cfg
        .redirect_uri
        .as_deref()
        .context("OIDC_REDIRECT_URI is required")?;

    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(issuer.to_string()).context("OIDC_ISSUER_URL is not a valid URL")?,
        async_http_client,
    )
    .await
    .with_context(|| format!("OIDC discovery failed for {issuer}"))?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_uri.to_string())
            .context("OIDC_REDIRECT_URI is not a valid URL")?,
    );

    Ok(client)
}
