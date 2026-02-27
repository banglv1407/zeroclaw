//! Zalo Official Account mode — uses Zalo OA REST API.
//!
//! For business accounts via developers.zalo.me.

use crate::channels::traits::{Channel, ChannelMessage, SendMessage};
use anyhow::{Context, Result};

use super::client::business::ZaloBusiness;

/// Zalo OA channel — uses access token.
pub struct ZaloOfficialChannel {
    business: ZaloBusiness,
    access_token: Option<String>,
    connected: bool,
}

impl ZaloOfficialChannel {
    pub fn new() -> Self {
        Self {
            business: ZaloBusiness::new(),
            access_token: None,
            connected: false,
        }
    }

    /// Set access token from OA developer portal.
    pub fn set_access_token(&mut self, token: &str) {
        self.access_token = Some(token.to_string());
        self.connected = true;
    }
}

#[async_trait::async_trait]
impl Channel for ZaloOfficialChannel {
    fn name(&self) -> &str {
        "zalo-oa"
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No access token"))?;
        self.business
            .send_oa_message(&message.recipient, &message.content, token)
            .await
            .map_err(|e| anyhow::anyhow!("OA send error: {}", e))
    }

    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Result<()> {
        futures_util::future::pending::<()>().await;
        Ok(())
    }

    async fn health_check(&self) -> bool {
        self.connected
    }
}

impl ZaloOfficialChannel {
    pub async fn connect(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            return Err(anyhow::anyhow!("Set access_token first"));
        }
        tracing::info!("Zalo OA channel connected");
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

impl Default for ZaloOfficialChannel {
    fn default() -> Self {
        Self::new()
    }
}
