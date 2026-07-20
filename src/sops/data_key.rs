use std::io::Read;

use age_core::format::{FileKey, Stanza};
use sha2::{Digest, Sha256};

use crate::{
    sops::metadata::{PivP256Stanza, SopsAgeEntry, SopsMetadata},
    yubikey_probe::{RecipientInfo, RecipientReport},
    Result,
};

pub struct DataKey {
    bytes: Vec<u8>,
}

impl DataKey {
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(format!(
                "SOPS data key is {} bytes; expected 32",
                bytes.len()
            ));
        }
        Ok(Self { bytes })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Decrypt a raw armored age file (e.g. `secrets/key.txt`) with a connected
/// YubiKey, natively — no `age`/`age-plugin-yubikey` binaries. Tries each
/// connected recipient; the one whose PIV slot matches the file's stanza wins
/// (non-matching recipients fail the tag check before any PIN prompt).
pub fn decrypt_age_file(ciphertext: &[u8], report: &RecipientReport) -> Result<Vec<u8>> {
    for info in &report.recipients {
        for recipient in info.all_recipients() {
            let identity = PivP256Identity {
                recipient: recipient.to_string(),
                yubikey_info: info.clone(),
            };
            let armored = age::armor::ArmoredReader::new(ciphertext);
            let Ok(decryptor) = age::Decryptor::new(armored) else {
                continue;
            };
            let Ok(mut reader) =
                decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
            else {
                continue;
            };
            let mut plaintext = Vec::new();
            if reader.read_to_end(&mut plaintext).is_ok() {
                return Ok(plaintext);
            }
        }
    }
    Err("no connected YubiKey could decrypt the age file".to_string())
}

pub fn decrypt_first(metadata: &SopsMetadata, report: &RecipientReport) -> Result<DataKey> {
    for entry in metadata.entries() {
        let Some(info) = report.find_recipient(&entry.recipient) else {
            continue;
        };
        return decrypt_entry(entry, info);
    }

    Err("no connected YubiKey recipient can decrypt this SOPS file".to_string())
}

fn decrypt_entry(entry: &SopsAgeEntry, info: &RecipientInfo) -> Result<DataKey> {
    let identity = PivP256Identity {
        recipient: entry.recipient.clone(),
        yubikey_info: info.clone(),
    };
    let enc = entry
        .encrypted_age_block
        .as_deref()
        .ok_or_else(|| "SOPS metadata did not retain original age block".to_string())?;

    let armored = age::armor::ArmoredReader::new(enc.as_bytes());
    let decryptor =
        age::Decryptor::new(armored).map_err(|err| format!("age payload parse failed: {err}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|err| format!("age payload decrypt failed: {err}"))?;
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read decrypted SOPS data key: {err}"))?;
    Ok(DataKey { bytes })
}

struct PivP256Identity {
    recipient: String,
    yubikey_info: RecipientInfo,
}

impl age::Identity for PivP256Identity {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        if stanza.tag != "piv-p256" || stanza.args.len() != 2 || stanza.body.len() != 32 {
            return None;
        }

        let piv = PivP256Stanza {
            tag_arg: &stanza.args[0],
            ephemeral_key_arg: &stanza.args[1],
            encrypted_file_key: &stanza.body,
        };
        match crate::sops::unwrap::unwrap_piv_p256(&self.recipient, piv, &self.yubikey_info) {
            Ok(key) => Some(Ok(FileKey::new(Box::new(key)))),
            Err(err) => {
                eprintln!("YubiKey age unwrap failed: {err}");
                Some(Err(age::DecryptError::KeyDecryptionFailed))
            }
        }
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
