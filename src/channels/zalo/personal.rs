//! Zalo Personal mode — wraps the low-level client modules.
//!
//! Provides a high-level Channel interface using reverse-engineered
//! Zalo Web protocol (auth, messaging, WebSocket listener).

use crate::channels::traits::{Channel, ChannelMessage, SendMessage};
use anyhow::{Context, Result};

use super::client::{
    auth::{ZaloAuth, ZaloCredentials},
    messaging::{ThreadType as ZaloThreadType, ZaloMessaging},
    session::SessionManager,
};

/// Zalo Personal channel — uses cookie/QR login.
pub struct ZaloPersonalChannel {
    auth: ZaloAuth,
    messaging: ZaloMessaging,
    session: SessionManager,
    connected: bool,
    cookie: Option<String>,
}

impl ZaloPersonalChannel {
    pub fn new(imei: &str, user_agent: &str) -> Self {
        let creds = ZaloCredentials {
            imei: imei.to_string(),
            cookie: None,
            phone: None,
            user_agent: user_agent.to_string(),
        };
        Self {
            auth: ZaloAuth::new(creds),
            messaging: ZaloMessaging::new(),
            session: SessionManager::new(),
            connected: false,
            cookie: None,
        }
    }

    /// Login with cookie.
    pub async fn login_cookie(&mut self, cookie: &str) -> Result<()> {
        let login_data = self.auth.login_with_cookie(cookie).await?;
        self.session
            .set_session(
                login_data.uid.clone(),
                login_data.zpw_enk,
                login_data.zpw_key,
            )
            .await;
        self.cookie = Some(cookie.to_string());
        self.connected = true;
        tracing::info!("Zalo Personal logged in: uid={}", login_data.uid);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Channel for ZaloPersonalChannel {
    fn name(&self) -> &str {
        "zalo-personal"
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        let cookie = self
            .cookie
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not logged in"))?;
        self.messaging
            .send_text(
                &message.recipient,
                ZaloThreadType::User,
                &message.content,
                cookie,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Zalo send error: {}", e))?;
        Ok(())
    }

    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Result<()> {
        futures_util::future::pending::<()>().await;
        Ok(())
    }

    async fn health_check(&self) -> bool {
        self.connected
    }
}

impl ZaloPersonalChannel {
    pub async fn connect(&mut self) -> Result<()> {
        if self.cookie.is_none() {
            return Err(anyhow::anyhow!("Call login_cookie() first"));
        }
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.session.invalidate().await;
        self.connected = false;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }
}
