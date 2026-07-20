use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_yaml::{Mapping, Number, Value};

use crate::{
    exec_status,
    sops::data_key::DataKey,
    sops::values::{
        additional_data, encrypt_sops_bytes, encrypt_sops_value, is_encrypted_value,
        mac_for_plain_value, CryptRules,
    },
    Result,
};

pub fn edit_yaml_file(file: &Path, data_key: &DataKey, editor: OsString) -> Result<u8> {
    let encrypted_content = fs::read_to_string(file)
        .map_err(|err| format!("failed to read {}: {err}", file.display()))?;
    let encrypted_value: Value = serde_yaml::from_str(&encrypted_content)
        .map_err(|err| format!("failed to parse {}: {err}", file.display()))?;
    let rules = CryptRules::from_sops_metadata(&encrypted_value)?;
    let sops_metadata = root_sops_metadata(&encrypted_value)?.clone();
    let plain_value = decrypt_document(&encrypted_value, data_key.as_bytes())?;
    let plain_content = serde_yaml::to_string(&plain_value)
        .map_err(|err| format!("failed to render YAML: {err}"))?;

    let temp = TempFile::create(file)?;
    temp.write_secret(&plain_content)?;
    let status = exec_status(Command::new(editor).arg(temp.path()))?;
    if status != 0 {
        return Ok(status);
    }

    let edited_content = fs::read_to_string(temp.path())
        .map_err(|err| format!("failed to read edited temp file: {err}"))?;
    if edited_content == plain_content {
        eprintln!("SOPS: no changes");
        return Ok(0);
    }

    let edited_value: Value = serde_yaml::from_str(&edited_content)
        .map_err(|err| format!("edited YAML is invalid: {err}"))?;
    let encrypted_output = encrypt_document(&edited_value, sops_metadata, &rules, data_key)?;
    write_atomic(file, encrypted_output.as_bytes())?;
    eprintln!("SOPS: encrypted {}", file.display());
    Ok(0)
}

fn decrypt_document(value: &Value, key: &[u8]) -> Result<Value> {
    let mut path = Vec::new();
    decrypt_node(value, key, &mut path, true)
}

fn decrypt_node(value: &Value, key: &[u8], path: &mut Vec<String>, root: bool) -> Result<Value> {
    match value {
        Value::Mapping(mapping) => {
            let mut out = Mapping::new();
            for (key_value, child) in mapping {
                let Some(component) = yaml_key_string(key_value) else {
                    continue;
                };
                if root && component == "sops" {
                    continue;
                }
                path.push(component);
                out.insert(key_value.clone(), decrypt_node(child, key, path, false)?);
                path.pop();
            }
            Ok(Value::Mapping(out))
        }
        Value::Sequence(items) => items
            .iter()
            .map(|item| decrypt_node(item, key, path, false))
            .collect::<Result<Vec<_>>>()
            .map(Value::Sequence),
        Value::String(text) if is_encrypted_value(text)? => {
            let aad = additional_data(path);
            let bytes = crate::sops::values::decrypt_sops_value(text, key, &aad)?;
            plaintext_value(&bytes, ciphertext_kind(text)?.as_str())
        }
        _ => Ok(value.clone()),
    }
}

fn encrypt_document(
    plain: &Value,
    mut sops_metadata: Value,
    rules: &CryptRules,
    data_key: &DataKey,
) -> Result<String> {
    let last_modified = sops_metadata_string_from_mapping(&sops_metadata, "lastmodified")
        .ok_or_else(|| "SOPS metadata has no lastmodified".to_string())?
        .to_string();
    let mac = mac_for_plain_value(plain, rules)?;
    let encrypted_mac =
        encrypt_sops_bytes(mac.as_bytes(), "str", data_key.as_bytes(), &last_modified)?;
    set_sops_metadata_string(&mut sops_metadata, "mac", encrypted_mac)?;

    let mut path = Vec::new();
    let encrypted_body = encrypt_node(plain, data_key.as_bytes(), rules, &mut path)?;
    let Value::Mapping(mut root) = encrypted_body else {
        return Err("SOPS YAML root must be a mapping".to_string());
    };
    root.insert(Value::String("sops".to_string()), sops_metadata);
    serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|err| format!("failed to render YAML: {err}"))
}

fn encrypt_node(
    value: &Value,
    key: &[u8],
    rules: &CryptRules,
    path: &mut Vec<String>,
) -> Result<Value> {
    match value {
        Value::Mapping(mapping) => {
            let mut out = Mapping::new();
            for (key_value, child) in mapping {
                let Some(component) = yaml_key_string(key_value) else {
                    continue;
                };
                path.push(component);
                out.insert(key_value.clone(), encrypt_node(child, key, rules, path)?);
                path.pop();
            }
            Ok(Value::Mapping(out))
        }
        Value::Sequence(items) => items
            .iter()
            .map(|item| encrypt_node(item, key, rules, path))
            .collect::<Result<Vec<_>>>()
            .map(Value::Sequence),
        _ if rules.should_be_encrypted(path) => {
            if let Some(encrypted) = encrypt_sops_value(value, key, &additional_data(path))? {
                Ok(Value::String(encrypted))
            } else {
                Ok(value.clone())
            }
        }
        _ => Ok(value.clone()),
    }
}

fn plaintext_value(bytes: &[u8], kind: &str) -> Result<Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|err| format!("decrypted SOPS {kind} value is not UTF-8: {err}"))?;
    match kind {
        "str" | "comment" | "time" => Ok(Value::String(text.to_string())),
        "bool" => Ok(Value::Bool(text.eq_ignore_ascii_case("true"))),
        "int" => text
            .parse::<i64>()
            .map(|value| Value::Number(Number::from(value)))
            .map_err(|err| format!("decrypted int is invalid: {err}")),
        "float" => serde_yaml::from_str::<Value>(text)
            .map_err(|err| format!("decrypted float is invalid YAML scalar: {err}")),
        "bytes" => Err("native SOPS edit does not support bytes values yet".to_string()),
        other => Err(format!("unsupported SOPS value type: {other}")),
    }
}

fn ciphertext_kind(value: &str) -> Result<String> {
    let re = Regex::new(r",type:(?P<kind>[^\]]+)\]$")
        .map_err(|err| format!("invalid SOPS type regex: {err}"))?;
    re.captures(value)
        .and_then(|captures| captures.name("kind"))
        .map(|kind| kind.as_str().to_string())
        .ok_or_else(|| "SOPS ciphertext has no type".to_string())
}

fn root_sops_metadata(value: &Value) -> Result<&Value> {
    let Value::Mapping(root) = value else {
        return Err("SOPS YAML root must be a mapping".to_string());
    };
    root.get(Value::String("sops".to_string()))
        .ok_or_else(|| "SOPS document has no metadata".to_string())
}

fn sops_metadata_string_from_mapping<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    let Value::Mapping(metadata) = value else {
        return None;
    };
    metadata
        .get(Value::String(key.to_string()))
        .and_then(Value::as_str)
}

fn set_sops_metadata_string(value: &mut Value, key: &str, new_value: String) -> Result<()> {
    let Value::Mapping(metadata) = value else {
        return Err("SOPS metadata must be a mapping".to_string());
    };
    metadata.insert(Value::String(key.to_string()), Value::String(new_value));
    Ok(())
}

fn yaml_key_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn write_atomic(file: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = file.with_extension(format!(
        "{}.nox-tmp",
        file.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("tmp")
    ));
    fs::write(&tmp, bytes).map_err(|err| format!("failed to write {}: {err}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to chmod {}: {err}", tmp.display()))?;
    fs::rename(&tmp, file).map_err(|err| {
        format!(
            "failed to replace {} with {}: {err}",
            file.display(),
            tmp.display()
        )
    })
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn create(source: &Path) -> Result<Self> {
        let dir = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            env::temp_dir()
        };
        let stem = source
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("secret");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("system clock error: {err}"))?
            .as_nanos();
        let path = dir.join(format!(
            "nox-sops-edit-{}-{now}-{stem}",
            std::process::id()
        ));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_secret(&self, content: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|err| format!("failed to open {}: {err}", self.path.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|err| format!("failed to write {}: {err}", self.path.display()))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn yaml_edit_round_trip_reencrypts_and_keeps_mac_valid() {
        let data_key = DataKey::from_bytes(vec![7; 32]).unwrap();
        let plain = serde_yaml::from_str::<Value>(
            r#"
token: alpha
count: 3
public_unencrypted: clear
nested:
  enabled: true
"#,
        )
        .unwrap();
        let mut metadata = Mapping::new();
        metadata.insert(
            Value::String("lastmodified".to_string()),
            Value::String("2026-07-06T12:00:00Z".to_string()),
        );
        metadata.insert(
            Value::String("unencrypted_suffix".to_string()),
            Value::String("_unencrypted".to_string()),
        );
        metadata.insert(
            Value::String("mac".to_string()),
            Value::String(String::new()),
        );

        let rules_doc = with_sops_metadata(Value::Mapping(metadata.clone()));
        let rules = CryptRules::from_sops_metadata(&rules_doc).unwrap();
        let encrypted =
            encrypt_document(&plain, Value::Mapping(metadata), &rules, &data_key).unwrap();
        let encrypted_value = serde_yaml::from_str::<Value>(&encrypted).unwrap();
        let decrypted = decrypt_document(&encrypted_value, data_key.as_bytes()).unwrap();
        assert_eq!(decrypted["token"], Value::String("alpha".to_string()));
        assert_eq!(
            decrypted["public_unencrypted"],
            Value::String("clear".to_string())
        );

        let mut edited = decrypted;
        edited["token"] = Value::String("beta".to_string());
        let metadata = root_sops_metadata(&encrypted_value).unwrap().clone();
        let rules = CryptRules::from_sops_metadata(&encrypted_value).unwrap();
        let reencrypted = encrypt_document(&edited, metadata, &rules, &data_key).unwrap();
        let temp_path = temp_test_path("yaml-edit-round-trip.yaml");
        fs::write(&temp_path, &reencrypted).unwrap();
        let report = crate::sops::values::check_file(&temp_path, &data_key).unwrap();
        fs::remove_file(&temp_path).unwrap();

        assert_eq!(report.decrypted_values, 3);
        assert_eq!(report.encrypted_values, 3);
        assert!(report.mac_decrypted);
        assert!(report.mac_matches);

        let reencrypted_value = serde_yaml::from_str::<Value>(&reencrypted).unwrap();
        let decrypted_again = decrypt_document(&reencrypted_value, data_key.as_bytes()).unwrap();
        assert_eq!(decrypted_again["token"], Value::String("beta".to_string()));
        assert_eq!(
            decrypted_again["public_unencrypted"],
            Value::String("clear".to_string())
        );
    }

    fn with_sops_metadata(metadata: Value) -> Value {
        let mut root = Mapping::new();
        root.insert(Value::String("sops".to_string()), metadata);
        Value::Mapping(root)
    }

    fn temp_test_path(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("nox-{name}-{}-{now}", std::process::id()))
    }
}
