use crate::CommsChannel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelVerificationStatus {
    pub email: bool,
    pub discord: bool,
    pub telegram: bool,
    pub signal: bool,
}

impl ChannelVerificationStatus {
    pub fn from_db_row(email: bool, discord: bool, telegram: bool, signal: bool) -> Self {
        Self {
            email,
            discord,
            telegram,
            signal,
        }
    }

    pub fn from_verified_channels(channels: &[CommsChannel]) -> Self {
        Self {
            email: channels.contains(&CommsChannel::Email),
            discord: channels.contains(&CommsChannel::Discord),
            telegram: channels.contains(&CommsChannel::Telegram),
            signal: channels.contains(&CommsChannel::Signal),
        }
    }

    pub fn has_any_verified(&self) -> bool {
        self.email || self.discord || self.telegram || self.signal
    }

    pub fn verified_channels(&self) -> Vec<CommsChannel> {
        let mut channels = Vec::with_capacity(4);
        if self.email {
            channels.push(CommsChannel::Email);
        }
        if self.discord {
            channels.push(CommsChannel::Discord);
        }
        if self.telegram {
            channels.push(CommsChannel::Telegram);
        }
        if self.signal {
            channels.push(CommsChannel::Signal);
        }
        channels
    }

    pub fn is_verified(&self, channel: CommsChannel) -> bool {
        match channel {
            CommsChannel::Email => self.email,
            CommsChannel::Discord => self.discord,
            CommsChannel::Telegram => self.telegram,
            CommsChannel::Signal => self.signal,
        }
    }
}
