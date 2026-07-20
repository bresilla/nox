use crate::Result;
use bech32::{ToBase32, Variant};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use yubikey::piv::SlotId;

pub fn status() -> Result<StatusReport> {
    let mut context = yubikey::Context::open().map_err(|err| {
        format!("failed to open YubiKey context: {err}; ensure pcscd is installed and running")
    })?;
    let readers = context
        .iter()
        .map_err(|err| format!("failed to list smart-card readers: {err}"))?
        .map(|reader| {
            let name = reader.name().into_owned();
            let yubikey = match reader.open() {
                Ok(yk) => Some(YubiKeyInfo {
                    serial: yk.serial().to_string(),
                    version: yk.version().to_string(),
                }),
                Err(_) => None,
            };
            ReaderInfo { name, yubikey }
        })
        .collect();

    Ok(StatusReport { readers })
}

pub fn recipients() -> Result<RecipientReport> {
    let mut context = yubikey::Context::open().map_err(|err| {
        format!("failed to open YubiKey context: {err}; ensure pcscd is installed and running")
    })?;
    let mut recipients = Vec::new();

    for reader in context
        .iter()
        .map_err(|err| format!("failed to list smart-card readers: {err}"))?
    {
        let mut yubikey = match reader.open() {
            Ok(yubikey) => yubikey,
            Err(_) => continue,
        };
        let serial = yubikey.serial().to_string();
        let keys = yubikey::Key::list(&mut yubikey)
            .map_err(|err| format!("failed to list PIV keys on YubiKey {serial}: {err}"))?;

        for key in keys {
            let SlotId::Retired(slot) = key.slot() else {
                continue;
            };
            let Some(age_recipients) = age_recipients(key.certificate()) else {
                continue;
            };
            recipients.push(RecipientInfo {
                serial: serial.clone(),
                slot: slot.to_string(),
                slot_id: slot.into(),
                tag_recipient: age_recipients.tag,
                yubikey_recipient: age_recipients.yubikey,
            });
        }
    }

    Ok(RecipientReport { recipients })
}

fn age_recipients(cert: &yubikey::Certificate) -> Option<AgeRecipients> {
    let spki = cert.subject_pki();
    let public_key = spki.subject_public_key.as_bytes()?;
    let public_key = p256::PublicKey::from_sec1_bytes(public_key).ok()?;
    let compressed = public_key.to_encoded_point(true);
    let tag = bech32::encode(
        "age1tag",
        compressed.as_bytes().to_base32(),
        Variant::Bech32,
    )
    .ok()?;
    let yubikey = bech32::encode(
        "age1yubikey",
        compressed.as_bytes().to_base32(),
        Variant::Bech32,
    )
    .ok()?;

    Some(AgeRecipients { tag, yubikey })
}

pub struct StatusReport {
    pub readers: Vec<ReaderInfo>,
}

pub struct ReaderInfo {
    pub name: String,
    pub yubikey: Option<YubiKeyInfo>,
}

pub struct YubiKeyInfo {
    pub serial: String,
    pub version: String,
}

pub struct RecipientReport {
    pub recipients: Vec<RecipientInfo>,
}

impl RecipientReport {
    pub fn find_recipient(&self, recipient: &str) -> Option<&RecipientInfo> {
        self.recipients
            .iter()
            .find(|info| info.all_recipients().contains(&recipient))
    }
}

#[derive(Clone)]
pub struct RecipientInfo {
    pub serial: String,
    pub slot: String,
    pub slot_id: u8,
    pub tag_recipient: String,
    pub yubikey_recipient: String,
}

impl RecipientInfo {
    pub fn all_recipients(&self) -> [&str; 2] {
        [&self.tag_recipient, &self.yubikey_recipient]
    }
}

struct AgeRecipients {
    tag: String,
    yubikey: String,
}

impl StatusReport {
    pub fn has_reader(&self) -> bool {
        !self.readers.is_empty()
    }
}
