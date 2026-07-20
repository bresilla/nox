use std::{fs, path::Path};

use aes::Aes256;
use aes_gcm::{
    aead::{consts::U32, generic_array::GenericArray, Aead, KeyInit, Payload},
    AesGcm,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use regex::Regex;
use serde_yaml::Value;
use sha2::{Digest, Sha512};

use crate::{sops::data_key::DataKey, Result};

type SopsAes256Gcm = AesGcm<Aes256, U32>;

pub struct CheckReport {
    pub encrypted_values: usize,
    pub decrypted_values: usize,
    pub mac_decrypted: bool,
    pub mac_matches: bool,
}

pub fn check_file(path: &Path, data_key: &DataKey) -> Result<CheckReport> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let value: Value = serde_yaml::from_str(&content)
        .map_err(|err| format!("failed to parse SOPS document: {err}"))?;
    check_value(&value, data_key)
}

fn check_value(value: &Value, data_key: &DataKey) -> Result<CheckReport> {
    let mut report = CheckReport {
        encrypted_values: 0,
        decrypted_values: 0,
        mac_decrypted: false,
        mac_matches: false,
    };
    let re = encrypted_value_regex()?;
    let key = data_key.as_bytes();
    if key.len() != 32 {
        return Err(format!("SOPS data key is {} bytes; expected 32", key.len()));
    }
    let rules = CryptRules::from_sops_metadata(value)?;
    let mut mac = Sha512::new();
    if rules.mac_only_encrypted {
        mac.update(MAC_ONLY_ENCRYPTED_INITIALIZATION);
    }

    walk(
        value,
        key,
        &re,
        &rules,
        &mut mac,
        &mut Vec::new(),
        &mut report,
    )?;
    if let Some(encrypted_mac) = sops_metadata_string(value, "mac") {
        let last_modified = sops_metadata_string(value, "lastmodified")
            .ok_or_else(|| "SOPS metadata has mac but no lastmodified".to_string())?;
        let stored_mac = decrypt_sops_value_with_regex(encrypted_mac, key, last_modified, &re)
            .map_err(|err| format!("failed to decrypt SOPS MAC: {err}"))?;
        let stored_mac =
            String::from_utf8(stored_mac).map_err(|err| format!("SOPS MAC is not UTF-8: {err}"))?;
        let computed_mac = hex_upper(&mac.finalize());
        report.mac_matches = stored_mac == computed_mac;
        if !report.mac_matches {
            return Err("SOPS MAC mismatch".to_string());
        }
        report.mac_decrypted = true;
    }
    Ok(report)
}

fn walk(
    value: &Value,
    key: &[u8],
    re: &Regex,
    rules: &CryptRules,
    mac: &mut Sha512,
    path: &mut Vec<String>,
    report: &mut CheckReport,
) -> Result<()> {
    match value {
        Value::Mapping(mapping) => {
            for (key_value, child) in mapping {
                let Some(component) = yaml_key_string(key_value) else {
                    continue;
                };
                if path.is_empty() && component == "sops" {
                    continue;
                }
                path.push(component);
                walk(child, key, re, rules, mac, path, report)?;
                path.pop();
            }
        }
        Value::Sequence(items) => {
            for item in items {
                walk(item, key, re, rules, mac, path, report)?;
            }
        }
        Value::String(text) if re.is_match(text) => {
            report.encrypted_values += 1;
            let aad = additional_data(path);
            let plaintext = decrypt_sops_value_with_regex(text, key, &aad, re)?;
            mac.update(&plaintext);
            report.decrypted_values += 1;
        }
        _ => {
            let encrypted = rules.should_be_encrypted(path);
            if !rules.mac_only_encrypted || encrypted {
                if let Some(bytes) = yaml_plain_bytes(value)? {
                    mac.update(bytes);
                }
            }
        }
    }
    Ok(())
}

pub fn is_encrypted_value(value: &str) -> Result<bool> {
    Ok(encrypted_value_regex()?.is_match(value))
}

pub fn decrypt_sops_value(value: &str, key: &[u8], aad: &str) -> Result<Vec<u8>> {
    decrypt_sops_value_with_regex(value, key, aad, &encrypted_value_regex()?)
}

fn decrypt_sops_value_with_regex(
    value: &str,
    key: &[u8],
    aad: &str,
    re: &Regex,
) -> Result<Vec<u8>> {
    let captures = re
        .captures(value)
        .ok_or_else(|| "value is not a SOPS AES256_GCM ciphertext".to_string())?;
    let data = decode(&captures["data"], "data")?;
    let iv = decode(&captures["iv"], "iv")?;
    let tag = decode(&captures["tag"], "tag")?;
    let mut payload = data;
    payload.extend_from_slice(&tag);

    let cipher =
        SopsAes256Gcm::new_from_slice(key).map_err(|err| format!("invalid AES key: {err}"))?;
    cipher
        .decrypt(
            GenericArray::from_slice(&iv),
            Payload {
                msg: &payload,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| format!("failed to decrypt SOPS value at aad '{aad}'"))
}

pub fn encrypt_sops_value(plaintext: &Value, key: &[u8], aad: &str) -> Result<Option<String>> {
    let Some((plain_bytes, kind)) = yaml_plain_value(plaintext)? else {
        return Ok(None);
    };
    encrypt_sops_bytes(&plain_bytes, kind, key, aad).map(Some)
}

pub fn encrypt_sops_bytes(plaintext: &[u8], kind: &str, key: &[u8], aad: &str) -> Result<String> {
    if key.len() != 32 {
        return Err(format!("SOPS data key is {} bytes; expected 32", key.len()));
    }
    let mut iv = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let cipher =
        SopsAes256Gcm::new_from_slice(key).map_err(|err| format!("invalid AES key: {err}"))?;
    let encrypted = cipher
        .encrypt(
            GenericArray::from_slice(&iv),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| format!("failed to encrypt SOPS value at aad '{aad}'"))?;
    let (data, tag) = encrypted.split_at(encrypted.len() - 16);
    Ok(format!(
        "ENC[AES256_GCM,data:{},iv:{},tag:{},type:{}]",
        STANDARD.encode(data),
        STANDARD.encode(iv),
        STANDARD.encode(tag),
        kind
    ))
}

fn decode(value: &str, label: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|err| format!("failed to decode SOPS {label}: {err}"))
}

pub fn additional_data(path: &[String]) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!("{}:", path.join(":"))
    }
}

fn yaml_key_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn sops_metadata_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    let Value::Mapping(root) = value else {
        return None;
    };
    let sops = root.get(Value::String("sops".to_string()))?;
    let Value::Mapping(metadata) = sops else {
        return None;
    };
    metadata
        .get(Value::String(key.to_string()))
        .and_then(Value::as_str)
}

fn sops_metadata_bool(value: &Value, key: &str) -> bool {
    let Value::Mapping(root) = value else {
        return false;
    };
    let Some(sops) = root.get(Value::String("sops".to_string())) else {
        return false;
    };
    let Value::Mapping(metadata) = sops else {
        return false;
    };
    metadata
        .get(Value::String(key.to_string()))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn encrypted_value_regex() -> Result<Regex> {
    Regex::new(
        r"^ENC\[AES256_GCM,data:(?P<data>[^,]+),iv:(?P<iv>[^,]+),tag:(?P<tag>[^,]+),type:(?P<kind>[^\]]+)\]$",
    )
    .map_err(|err| format!("invalid SOPS ciphertext regex: {err}"))
}

pub struct CryptRules {
    unencrypted_suffix: Option<String>,
    encrypted_suffix: Option<String>,
    unencrypted_regex: Option<Regex>,
    encrypted_regex: Option<Regex>,
    pub mac_only_encrypted: bool,
}

impl CryptRules {
    pub fn from_sops_metadata(value: &Value) -> Result<Self> {
        let explicit_unencrypted_suffix =
            sops_metadata_string(value, "unencrypted_suffix").map(ToOwned::to_owned);
        let encrypted_suffix =
            sops_metadata_string(value, "encrypted_suffix").map(ToOwned::to_owned);
        let unencrypted_regex = optional_regex(value, "unencrypted_regex")?;
        let encrypted_regex = optional_regex(value, "encrypted_regex")?;
        let has_rule = explicit_unencrypted_suffix.is_some()
            || encrypted_suffix.is_some()
            || unencrypted_regex.is_some()
            || encrypted_regex.is_some()
            || sops_metadata_string(value, "unencrypted_comment_regex").is_some()
            || sops_metadata_string(value, "encrypted_comment_regex").is_some();
        Ok(Self {
            unencrypted_suffix: explicit_unencrypted_suffix
                .or_else(|| (!has_rule).then(|| "_unencrypted".to_string())),
            encrypted_suffix,
            unencrypted_regex,
            encrypted_regex,
            mac_only_encrypted: sops_metadata_bool(value, "mac_only_encrypted"),
        })
    }

    pub fn should_be_encrypted(&self, path: &[String]) -> bool {
        let mut encrypted = true;
        if let Some(suffix) = &self.unencrypted_suffix {
            if path.iter().any(|component| component.ends_with(suffix)) {
                encrypted = false;
            }
        }
        if let Some(suffix) = &self.encrypted_suffix {
            encrypted = path.iter().any(|component| component.ends_with(suffix));
        }
        if let Some(regex) = &self.unencrypted_regex {
            if path.iter().any(|component| regex.is_match(component)) {
                encrypted = false;
            }
        }
        if let Some(regex) = &self.encrypted_regex {
            encrypted = path.iter().any(|component| regex.is_match(component));
        }
        encrypted
    }
}

fn optional_regex(value: &Value, key: &str) -> Result<Option<Regex>> {
    sops_metadata_string(value, key)
        .map(|pattern| Regex::new(pattern).map_err(|err| format!("invalid SOPS {key}: {err}")))
        .transpose()
}

pub fn mac_for_plain_value(value: &Value, rules: &CryptRules) -> Result<String> {
    let mut mac = Sha512::new();
    if rules.mac_only_encrypted {
        mac.update(MAC_ONLY_ENCRYPTED_INITIALIZATION);
    }
    walk_plain_mac(value, rules, &mut mac, &mut Vec::new())?;
    Ok(hex_upper(&mac.finalize()))
}

fn walk_plain_mac(
    value: &Value,
    rules: &CryptRules,
    mac: &mut Sha512,
    path: &mut Vec<String>,
) -> Result<()> {
    match value {
        Value::Mapping(mapping) => {
            for (key_value, child) in mapping {
                let Some(component) = yaml_key_string(key_value) else {
                    continue;
                };
                if path.is_empty() && component == "sops" {
                    continue;
                }
                path.push(component);
                walk_plain_mac(child, rules, mac, path)?;
                path.pop();
            }
        }
        Value::Sequence(items) => {
            for item in items {
                walk_plain_mac(item, rules, mac, path)?;
            }
        }
        _ => {
            let encrypted = rules.should_be_encrypted(path);
            if !rules.mac_only_encrypted || encrypted {
                if let Some(bytes) = yaml_plain_bytes(value)? {
                    mac.update(bytes);
                }
            }
        }
    }
    Ok(())
}

fn yaml_plain_bytes(value: &Value) -> Result<Option<Vec<u8>>> {
    Ok(yaml_plain_value(value)?.map(|(bytes, _)| bytes))
}

fn yaml_plain_value(value: &Value) -> Result<Option<(Vec<u8>, &'static str)>> {
    match value {
        Value::Null | Value::Mapping(_) | Value::Sequence(_) => Ok(None),
        Value::String(value) => Ok(Some((value.as_bytes().to_vec(), "str"))),
        Value::Bool(value) => Ok(Some((
            if *value {
                b"True".to_vec()
            } else {
                b"False".to_vec()
            },
            "bool",
        ))),
        Value::Number(value) => {
            let kind = if value.as_i64().is_some() || value.as_u64().is_some() {
                "int"
            } else {
                "float"
            };
            Ok(Some((value.to_string().into_bytes(), kind)))
        }
        Value::Tagged(tagged) => yaml_plain_value(&tagged.value),
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

const MAC_ONLY_ENCRYPTED_INITIALIZATION: &[u8] = &[
    0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0x0b,
    0x0b, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69,
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decrypts_sops_value_with_32_byte_nonce() {
        let key = [7_u8; 32];
        let iv = [9_u8; 32];
        let cipher = SopsAes256Gcm::new_from_slice(&key).unwrap();
        let encrypted = cipher
            .encrypt(
                GenericArray::from_slice(&iv),
                Payload {
                    msg: b"secret",
                    aad: b"token:",
                },
            )
            .unwrap();
        let value = format!(
            "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]",
            STANDARD.encode(&encrypted[..encrypted.len() - 16]),
            STANDARD.encode(iv),
            STANDARD.encode(&encrypted[encrypted.len() - 16..])
        );

        let decrypted = decrypt_sops_value(&value, &key, "token:").unwrap();
        assert_eq!(decrypted, b"secret");
    }

    #[test]
    fn additional_data_matches_sops_path_format() {
        assert_eq!(additional_data(&[]), "");
        assert_eq!(additional_data(&["one".into()]), "one:");
        assert_eq!(additional_data(&["one".into(), "two".into()]), "one:two:");
    }

    #[test]
    fn crypt_rules_default_to_unencrypted_suffix() {
        let rules =
            CryptRules::from_sops_metadata(&serde_yaml::from_str("sops: {}\n").unwrap()).unwrap();
        assert!(rules.should_be_encrypted(&["token".into()]));
        assert!(!rules.should_be_encrypted(&["token_unencrypted".into()]));
    }
}
