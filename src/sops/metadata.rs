use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use serde_yaml::Value;

use crate::Result;

#[derive(Debug)]
pub struct SopsMetadata {
    recipients: BTreeSet<String>,
    entries: Vec<SopsAgeEntry>,
}

#[derive(Debug)]
pub struct SopsAgeEntry {
    pub recipient: String,
    pub encrypted_age_block: Option<String>,
    pub stanzas: Vec<AgeStanza>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AgeStanza {
    pub stanza_type: String,
    pub args: Vec<String>,
    pub body_len: usize,
    pub body: Vec<u8>,
}

impl SopsMetadata {
    pub fn load(file: &Path) -> Result<Self> {
        let content = fs::read_to_string(file)
            .map_err(|err| format!("failed to read {}: {err}", file.display()))?;
        Self::parse(&content).map_err(|err| format!("{}: {err}", file.display()))
    }

    fn parse(content: &str) -> Result<Self> {
        let value: Value = serde_yaml::from_str(content)
            .map_err(|err| format!("failed to parse SOPS document: {err}"))?;
        let entries = extract_entries(&value)?;
        let recipients = entries
            .iter()
            .map(|entry| entry.recipient.clone())
            .collect::<BTreeSet<_>>();
        if recipients.is_empty() {
            return Err("no age recipients found in SOPS metadata".to_string());
        }
        Ok(Self {
            recipients,
            entries,
        })
    }

    pub fn recipients(&self) -> &BTreeSet<String> {
        &self.recipients
    }

    pub fn entries(&self) -> &[SopsAgeEntry] {
        &self.entries
    }
}

impl AgeStanza {
    pub fn is_yubikey(&self) -> bool {
        self.stanza_type == "piv-p256"
    }

    pub fn unwrap_check(&self) -> UnwrapCheck {
        if !self.is_yubikey() {
            return UnwrapCheck {
                ok: false,
                reason: "not a YubiKey piv-p256 stanza".to_string(),
            };
        }
        if self.args.len() != 2 {
            return UnwrapCheck {
                ok: false,
                reason: format!("expected 2 stanza args, found {}", self.args.len()),
            };
        }
        if self.body_len != 32 {
            return UnwrapCheck {
                ok: false,
                reason: format!(
                    "expected 32-byte encrypted file-key body, found {}",
                    self.body_len
                ),
            };
        }
        UnwrapCheck {
            ok: true,
            reason: "ready for native YubiKey unwrap".to_string(),
        }
    }

    pub fn piv_p256(&self) -> Option<PivP256Stanza<'_>> {
        if !self.is_yubikey() || self.args.len() != 2 || self.body.len() != 32 {
            return None;
        }
        Some(PivP256Stanza {
            tag_arg: &self.args[0],
            ephemeral_key_arg: &self.args[1],
            encrypted_file_key: &self.body,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UnwrapCheck {
    pub ok: bool,
    pub reason: String,
}

pub struct PivP256Stanza<'a> {
    pub tag_arg: &'a str,
    pub ephemeral_key_arg: &'a str,
    pub encrypted_file_key: &'a [u8],
}

fn extract_entries(value: &Value) -> Result<Vec<SopsAgeEntry>> {
    let Some(sops) = mapping_get(value, "sops") else {
        return Ok(Vec::new());
    };
    let Some(age) = mapping_get(sops, "age") else {
        return Ok(Vec::new());
    };
    let Value::Sequence(entries) = age else {
        return Ok(Vec::new());
    };

    entries
        .iter()
        .filter_map(|entry| {
            let recipient = mapping_get(entry, "recipient")?.as_str()?;
            let enc = mapping_get(entry, "enc")?.as_str()?;
            recipient
                .starts_with("age1")
                .then_some((recipient.to_string(), enc))
        })
        .map(|(recipient, enc)| {
            let stanzas = parse_age_stanzas(enc)?;
            Ok(SopsAgeEntry {
                recipient,
                encrypted_age_block: Some(enc.to_string()),
                stanzas,
            })
        })
        .collect()
}

fn parse_age_stanzas(armored: &str) -> Result<Vec<AgeStanza>> {
    let decoded = decode_age_armor(armored)?;
    let mut stanzas = Vec::new();
    let mut pending: Option<PendingStanza> = None;

    for line in decoded.split(|byte| *byte == b'\n') {
        if line.starts_with(b"--- ") {
            push_pending_stanza(&mut stanzas, pending.take())?;
            break;
        }
        if let Some(rest) = line.strip_prefix(b"-> ") {
            push_pending_stanza(&mut stanzas, pending.take())?;
            let rest = std::str::from_utf8(rest)
                .map_err(|err| format!("age stanza header is not UTF-8: {err}"))?;
            let mut parts = rest.split_whitespace();
            let Some(stanza_type) = parts.next() else {
                continue;
            };
            pending = Some(PendingStanza {
                stanza_type: stanza_type.to_string(),
                args: parts.map(ToOwned::to_owned).collect(),
                body: String::new(),
            });
            continue;
        }
        if let Some(pending) = pending.as_mut() {
            if line.is_empty() {
                continue;
            }
            let body_line = std::str::from_utf8(line)
                .map_err(|err| format!("age stanza body is not UTF-8: {err}"))?;
            pending.body.push_str(body_line.trim());
        }
    }
    push_pending_stanza(&mut stanzas, pending.take())?;

    if stanzas.is_empty() {
        return Err("age block has no recipient stanzas".to_string());
    }

    Ok(stanzas)
}

fn push_pending_stanza(stanzas: &mut Vec<AgeStanza>, pending: Option<PendingStanza>) -> Result<()> {
    let Some(pending) = pending else {
        return Ok(());
    };
    let body = decode_stanza_body(&pending.body)?;
    stanzas.push(AgeStanza {
        stanza_type: pending.stanza_type,
        args: pending.args,
        body_len: body.len(),
        body,
    });
    Ok(())
}

fn decode_stanza_body(body: &str) -> Result<Vec<u8>> {
    if body.is_empty() {
        return Err("age stanza has empty body".to_string());
    }
    STANDARD_NO_PAD
        .decode(body.as_bytes())
        .or_else(|_| STANDARD.decode(body.as_bytes()))
        .map_err(|err| format!("failed to decode age stanza body: {err}"))
}

struct PendingStanza {
    stanza_type: String,
    args: Vec<String>,
    body: String,
}

fn decode_age_armor(armored: &str) -> Result<Vec<u8>> {
    let mut in_body = false;
    let mut encoded = String::new();

    for line in armored.lines().map(str::trim) {
        match line {
            "-----BEGIN AGE ENCRYPTED FILE-----" => in_body = true,
            "-----END AGE ENCRYPTED FILE-----" => break,
            _ if in_body && !line.is_empty() => encoded.push_str(line),
            _ => {}
        }
    }

    if encoded.is_empty() {
        return Err("missing age ASCII armor body".to_string());
    }

    STANDARD
        .decode(encoded.as_bytes())
        .map_err(|err| format!("failed to decode age ASCII armor: {err}"))
}

fn mapping_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Mapping(mapping) = value else {
        return None;
    };
    mapping.get(Value::String(key.to_string()))
}

#[cfg(test)]
mod tests {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
        Engine as _,
    };

    use super::SopsMetadata;

    #[test]
    fn extracts_yaml_sops_recipients() {
        let metadata = SopsMetadata::parse(&format!(
            r#"
secret: ENC[AES256_GCM,data]
sops:
  age:
    - recipient: age1yubikey1abc123
      enc: |
{}
    - recipient: age1system456
      enc: |
{}
  version: 3.13.2
"#,
            indented_armor(&age_text("piv-p256 tag epk")),
            indented_armor(&age_text("X25519 abc def")),
        ))
        .unwrap();

        assert!(metadata.recipients().contains("age1yubikey1abc123"));
        assert!(metadata.recipients().contains("age1system456"));
        assert!(metadata.entries()[0].stanzas[0].is_yubikey());
        assert_eq!(metadata.entries()[0].stanzas[0].body_len, 32);
        assert!(metadata.entries()[0].stanzas[0].unwrap_check().ok);
        assert_eq!(metadata.entries()[1].stanzas[0].stanza_type, "X25519");
    }

    #[test]
    fn extracts_json_sops_recipients() {
        let yubikey_armor = armor(&age_text("piv-p256 tag epk")).replace('\n', "\\n");
        let system_armor = armor(&age_text("X25519 abc def")).replace('\n', "\\n");
        let metadata = SopsMetadata::parse(&format!(
            r#"{{
  "data": "ENC[AES256_GCM,data]",
  "sops": {{
    "age": [
      {{ "recipient": "age1yubikey1abc123", "enc": "{yubikey_armor}" }},
      {{ "recipient": "age1system456", "enc": "{system_armor}" }}
    ],
    "version": "3.13.2"
  }}
}}"#
        ))
        .unwrap();

        assert_eq!(
            metadata.recipients().iter().cloned().collect::<Vec<_>>(),
            vec!["age1system456", "age1yubikey1abc123"]
        );
    }

    #[test]
    fn rejects_files_without_sops_age_recipients() {
        let err = SopsMetadata::parse("{ plain: true }").unwrap_err();
        assert!(err.contains("no age recipients"));
    }

    #[test]
    fn unwrap_check_rejects_bad_yubikey_shape() {
        let metadata = SopsMetadata::parse(&format!(
            r#"
sops:
  age:
    - recipient: age1yubikey1abc123
      enc: |
{}
"#,
            indented_armor("age-encryption.org/v1\n-> piv-p256 only-one-arg\nYWJj\n--- mac\n"),
        ))
        .unwrap();

        let check = metadata.entries()[0].stanzas[0].unwrap_check();
        assert!(!check.ok);
        assert!(check.reason.contains("expected 2 stanza args"));
    }

    fn armor(text: &str) -> String {
        format!(
            "-----BEGIN AGE ENCRYPTED FILE-----\n{}\n-----END AGE ENCRYPTED FILE-----\n",
            STANDARD.encode(text)
        )
    }

    fn indented_armor(text: &str) -> String {
        armor(text)
            .lines()
            .map(|line| format!("        {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn age_text(stanza: &str) -> String {
        format!(
            "age-encryption.org/v1\n-> {stanza}\n{}\n--- mac\n",
            STANDARD_NO_PAD.encode([7_u8; 32])
        )
    }
}
