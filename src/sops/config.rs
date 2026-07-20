use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;

use crate::Result;

#[derive(Debug)]
pub struct SopsConfig {
    rules: Vec<CreationRule>,
}

#[derive(Debug)]
pub struct RuleMatch {
    pub path_regex: String,
    pub recipients: BTreeSet<String>,
}

#[derive(Debug)]
struct CreationRule {
    path_regex: String,
    recipients: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    creation_rules: Vec<RawCreationRule>,
}

#[derive(Debug, Deserialize)]
struct RawCreationRule {
    path_regex: Option<String>,
    #[serde(default)]
    key_groups: Vec<RawKeyGroup>,
}

#[derive(Debug, Deserialize)]
struct RawKeyGroup {
    #[serde(default)]
    age: Vec<String>,
}

impl SopsConfig {
    pub fn load(repo: &Path) -> Result<Self> {
        let file = repo.join("host/.sops.yaml");
        let content = fs::read_to_string(&file)
            .map_err(|err| format!("failed to read {}: {err}", file.display()))?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> Result<Self> {
        let raw: RawConfig = serde_yaml::from_str(content)
            .map_err(|err| format!("failed to parse .sops.yaml: {err}"))?;
        let rules = raw
            .creation_rules
            .into_iter()
            .filter_map(|rule| {
                let path_regex = rule.path_regex?;
                let recipients = rule
                    .key_groups
                    .into_iter()
                    .flat_map(|group| group.age)
                    .filter(|recipient| recipient.starts_with("age1"))
                    .collect::<BTreeSet<_>>();
                Some(CreationRule {
                    path_regex,
                    recipients,
                })
            })
            .collect();

        Ok(Self { rules })
    }

    pub fn match_file(&self, repo: &Path, file: &Path) -> Result<RuleMatch> {
        let relative = repo_relative_path(repo, file)?;
        for rule in &self.rules {
            let regex = Regex::new(&rule.path_regex).map_err(|err| {
                format!("invalid .sops.yaml path_regex '{}': {err}", rule.path_regex)
            })?;
            if regex.is_match(&relative) {
                if rule.recipients.is_empty() {
                    return Err(format!(
                        ".sops.yaml rule '{}' matched {}, but has no age recipients",
                        rule.path_regex, relative
                    ));
                }
                return Ok(RuleMatch {
                    path_regex: rule.path_regex.clone(),
                    recipients: rule.recipients.clone(),
                });
            }
        }

        Err(format!("no .sops.yaml creation rule matches {}", relative))
    }
}

fn repo_relative_path(repo: &Path, file: &Path) -> Result<String> {
    let file = absoluteish(file);
    let repo = absoluteish(repo);
    let relative = file
        .strip_prefix(&repo)
        .map_err(|_| format!("{} is not inside {}", file.display(), repo.display()))?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn absoluteish(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::SopsConfig;

    const CONFIG: &str = r#"
keys:
  - &operator_yubikey age1yubikey1abc
  - &system age1system123

creation_rules:
  - path_regex: secrets/system\.yaml$
    key_groups:
      - age:
          - *operator_yubikey
          - *system
  - path_regex: secrets/common/.*\.yaml$
    key_groups:
      - age:
          - *operator_yubikey
          - *system
"#;

    #[test]
    fn parses_recipients_from_anchored_rules() {
        let config = SopsConfig::parse(CONFIG).unwrap();
        let matched = config
            .match_file(Path::new("/repo"), Path::new("/repo/secrets/system.yaml"))
            .unwrap();

        assert_eq!(matched.path_regex, r"secrets/system\.yaml$");
        assert!(matched.recipients.contains("age1yubikey1abc"));
        assert!(matched.recipients.contains("age1system123"));
    }

    #[test]
    fn matches_common_yaml_rule() {
        let config = SopsConfig::parse(CONFIG).unwrap();
        let matched = config
            .match_file(
                Path::new("/repo"),
                Path::new("/repo/secrets/common/github.yaml"),
            )
            .unwrap();

        assert_eq!(matched.path_regex, r"secrets/common/.*\.yaml$");
    }
}
