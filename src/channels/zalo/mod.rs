//! Zalo channel module — Zalo Personal + OA.
//! Wraps the client sub-modules into the Channel trait.

pub mod client;
pub mod official;
pub mod personal;

use crate::channels::traits::{Channel, ChannelMessage, SendMessage};
use crate::config::schema::ZaloConfig;
use crate::config::Config;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use std::path::PathBuf;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use self::client::auth::{ZaloAuth, ZaloCredentials};
use self::client::messaging::{ThreadType as ZaloThreadType, ZaloMessaging};

const DEFAULT_ZALO_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";

struct ParsedIncomingMessage {
    id: String,
    sender: String,
    reply_target: String,
    content: String,
    timestamp: u64,
}

/// Zalo channel implementation — routes to Personal or OA mode.
pub struct ZaloChannel {
    config: ZaloConfig,
    config_path: PathBuf,
}

impl ZaloChannel {
    pub fn new(config: ZaloConfig, config_path: PathBuf) -> Self {
        Self {
            config,
            config_path,
        }
    }

    fn credentials(&self) -> ZaloCredentials {
        let imei = if self.config.personal.imei.trim().is_empty() {
            let id: u64 = rand::random::<u64>() % 99_999_999_999_999;
            format!("{id:014}")
        } else {
            self.config.personal.imei.clone()
        };

        let user_agent = if self.config.personal.user_agent.trim().is_empty() {
            DEFAULT_ZALO_USER_AGENT.to_string()
        } else {
            self.config.personal.user_agent.clone()
        };

        ZaloCredentials {
            imei,
            cookie: None,
            phone: None,
            user_agent,
        }
    }

    async fn build_messaging_client(
        &self,
        cookie: &str,
    ) -> Result<(ZaloMessaging, String, Vec<String>)> {
        let auth = ZaloAuth::new(self.credentials());
        let login_data = auth
            .login_with_cookie(cookie)
            .await
            .context("Zalo login with cookie failed")?;

        let mut messaging = ZaloMessaging::new();
        if let Some(ref map) = login_data.zpw_service_map_v3 {
            messaging.set_service_map(client::messaging::ZaloServiceMap::from_login_data(map));
        }
        messaging.set_login_info(&login_data.uid, login_data.zpw_enk.as_deref());

        Ok((
            messaging,
            login_data.uid,
            login_data.zpw_ws.unwrap_or_default(),
        ))
    }

    fn parse_send_target(recipient: &str) -> (String, ZaloThreadType) {
        if let Some(group_id) = recipient.strip_prefix("group:") {
            (group_id.trim().to_string(), ZaloThreadType::Group)
        } else {
            (recipient.trim().to_string(), ZaloThreadType::User)
        }
    }

    fn parse_ws_text_event(raw: &str, own_uid: &str) -> Option<ParsedIncomingMessage> {
        let payload: serde_json::Value = serde_json::from_str(raw).ok()?;
        if payload["cmd"].as_i64().unwrap_or_default() != 501 {
            return None;
        }

        let data = payload.get("data")?;
        let sender = data["uidFrom"]
            .as_str()
            .or_else(|| data["fromuid"].as_str())
            .or_else(|| data["fromUid"].as_str())
            .or_else(|| data["uid_from"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        if sender.is_empty() || sender == own_uid {
            return None;
        }

        let content = data["content"]
            .as_str()
            .or_else(|| data["msg"].as_str())
            .or_else(|| data["text"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        if content.is_empty() {
            return None;
        }

        let group_id = data["gid"]
            .as_str()
            .or_else(|| data["groupId"].as_str())
            .or_else(|| data["grid"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        let toid = data["toid"]
            .as_str()
            .or_else(|| data["toId"].as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        let reply_target = if !group_id.is_empty() {
            format!("group:{group_id}")
        } else if !toid.is_empty() && toid != own_uid {
            toid
        } else {
            sender.clone()
        };

        let timestamp = data["ts"]
            .as_u64()
            .or_else(|| data["ctime"].as_u64())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default()
            });

        let id = data["msgId"]
            .as_str()
            .or_else(|| data["msgid"].as_str())
            .or_else(|| data["messageId"].as_str())
            .map(str::to_string)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| format!("zalo_{timestamp}_{sender}"));

        Some(ParsedIncomingMessage {
            id,
            sender,
            reply_target,
            content,
            timestamp,
        })
    }

    /// Get QR code for login.
    pub async fn get_qr_code(&self) -> Result<client::auth::QrCodeResult> {
        let mut auth = ZaloAuth::new(self.credentials());
        auth.get_qr_code().await
    }

    fn cookie_path_from_runtime_config(&self) -> Option<String> {
        if self.config_path.as_os_str().is_empty() {
            return None;
        }

        let content = std::fs::read_to_string(&self.config_path).ok()?;
        let parsed: Config = toml::from_str(&content).ok()?;
        parsed.channels_config.zalo.and_then(|zalo| {
            let path = zalo.personal.cookie_path.trim().to_string();
            if path.is_empty() {
                None
            } else {
                Some(path)
            }
        })
    }

    fn cookie_from_path_or_literal(raw_path: &str) -> Result<Option<String>> {
        let path = raw_path.trim();
        if path.is_empty() {
            return Ok(None);
        }

        // Expand ~ to home dir.
        let expanded = if path.starts_with("~/") {
            std::env::var("HOME")
                .ok()
                .map(|h| std::path::PathBuf::from(h).join(&path[2..]))
                .unwrap_or_else(|| std::path::PathBuf::from(path))
        } else {
            std::path::PathBuf::from(path)
        };

        if expanded.exists() {
            let content = std::fs::read_to_string(&expanded)
                .with_context(|| format!("Failed to read cookie file: {}", expanded.display()))?;
            return Self::extract_cookie(content.trim());
        }

        Self::extract_cookie(path)
    }

    fn extract_cookie(raw: &str) -> Result<Option<String>> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        // Support JSON format {"cookie": "..."}.
        if trimmed.starts_with('{') {
            let json: serde_json::Value = serde_json::from_str(trimmed)
                .with_context(|| "Invalid JSON cookie payload for Zalo")?;
            if let Some(cookie) = json["cookie"].as_str().map(str::trim) {
                if !cookie.is_empty() {
                    return Ok(Some(cookie.to_string()));
                }
            }
            return Ok(None);
        }

        // Support raw cookie string.
        if trimmed.contains("zpw_") && (trimmed.contains("; ") || trimmed.contains('=')) {
            return Ok(Some(trimmed.to_string()));
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl Channel for ZaloChannel {
    fn name(&self) -> &str {
        "zalo"
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        if self.config.mode != "personal" {
            anyhow::bail!(
                "Zalo mode '{}' is not supported in runtime send yet",
                self.config.mode
            );
        }

        let cookie = self
            .try_load_cookie()?
            .ok_or_else(|| anyhow::anyhow!("No Zalo cookie found. Complete QR login first."))?;

        let (messaging, _uid, _ws_urls) = self.build_messaging_client(&cookie).await?;
        let (thread_id, thread_type) = Self::parse_send_target(&message.recipient);

        messaging
            .send_text(&thread_id, thread_type, &message.content, &cookie)
            .await
            .map_err(|e| anyhow::anyhow!("Zalo send error: {}", e))?;

        tracing::debug!("Zalo: message sent to {}", thread_id);
        Ok(())
    }

    async fn listen(&self, tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Result<()> {
        if self.config.mode != "personal" {
            tracing::warn!(
                "Zalo listener is only implemented for personal mode, configured mode={}",
                self.config.mode
            );
            futures_util::future::pending::<()>().await;
            return Ok(());
        }

        let cookie = self
            .try_load_cookie()?
            .ok_or_else(|| anyhow::anyhow!("No Zalo cookie found. Complete QR login first."))?;

        let (_messaging, own_uid, ws_urls) = self.build_messaging_client(&cookie).await?;
        let ws_url = ws_urls
            .into_iter()
            .find(|url| !url.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Zalo login did not return a websocket URL"))?;

        tracing::info!("Zalo listener: connecting websocket");
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| anyhow::anyhow!("Zalo websocket connect failed: {e}"))?;

        let (_write, mut read) = ws_stream.split();
        while let Some(frame) = read.next().await {
            match frame {
                Ok(WsMessage::Text(text)) => {
                    if let Some(incoming) = Self::parse_ws_text_event(text.as_ref(), &own_uid) {
                        tx.send(ChannelMessage {
                            id: incoming.id,
                            sender: incoming.sender,
                            reply_target: incoming.reply_target,
                            content: incoming.content,
                            channel: self.name().to_string(),
                            timestamp: incoming.timestamp,
                            thread_ts: None,
                        })
                        .await
                        .context("Zalo listener failed to forward incoming message")?;
                    }
                }
                Ok(WsMessage::Close(frame)) => {
                    anyhow::bail!("Zalo websocket closed: {:?}", frame);
                }
                Ok(_) => {}
                Err(e) => anyhow::bail!("Zalo websocket error: {e}"),
            }
        }

        anyhow::bail!("Zalo websocket stream ended")
    }

    async fn health_check(&self) -> bool {
        self.try_load_cookie()
            .map(|cookie| cookie.is_some())
            .unwrap_or(false)
    }

    async fn start_typing(&self, thread_id: &str) -> Result<()> {
        tracing::debug!(
            "Zalo: typing indicator to {} (not supported by API)",
            thread_id
        );
        Ok(())
    }
}

impl ZaloChannel {
    pub async fn connect(&mut self) -> Result<()> {
        if self.try_load_cookie()?.is_some() {
            Ok(())
        } else {
            anyhow::bail!(
                "No Zalo cookie found. Configure cookie_path in config.toml or use QR login via admin dashboard."
            )
        }
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        tracing::info!("Zalo channel: disconnected");
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.try_load_cookie().map(|v| v.is_some()).unwrap_or(false)
    }
}

impl ZaloChannel {
    /// Try to load cookie from cookie_path file.
    fn try_load_cookie(&self) -> Result<Option<String>> {
        if let Some(runtime_cookie_path) = self.cookie_path_from_runtime_config() {
            return Self::cookie_from_path_or_literal(&runtime_cookie_path);
        }

        let config_cookie_path = self.config.personal.cookie_path.trim().to_string();
        if !config_cookie_path.is_empty() {
            return Self::cookie_from_path_or_literal(&config_cookie_path);
        }

        Ok(None)
    }
}
