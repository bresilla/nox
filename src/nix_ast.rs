use std::fs;
use std::path::Path;

use rnix::Root;

use crate::Result;

pub fn parse_file(path: &Path) -> Result<ParseReport> {
    let source = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    parse_source(&source)
}

pub fn parse_source(source: &str) -> Result<ParseReport> {
    let parsed = Root::parse(source);
    Ok(ParseReport {
        errors: parsed.errors().iter().map(ToString::to_string).collect(),
        node_count: parsed.syntax().descendants().count(),
    })
}

pub struct ParseReport {
    pub errors: Vec<String>,
    pub node_count: usize,
}

impl ParseReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_source;

    #[test]
    fn parses_valid_nix_without_errors() {
        let report = parse_source("{ a = 1; b = { c = \"x\"; }; }").unwrap();
        assert!(report.is_ok());
        assert!(report.node_count > 0);
    }

    #[test]
    fn reports_errors_for_malformed_nix() {
        let report = parse_source("{ a = ; ").unwrap();
        assert!(!report.is_ok());
        assert!(!report.errors.is_empty());
    }
}
