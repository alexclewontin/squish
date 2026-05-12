use std::path::Path;

use crate::error::QsshError;

/// Load raw bytes from a key file.
pub fn load_key_bytes(path: &Path) -> Result<Vec<u8>, QsshError> {
    std::fs::read(path).map_err(|e| {
        QsshError::AuthFailed(format!("failed to read key at {}: {e}", path.display()))
    })
}

/// Parse an authorized_keys file.
///
/// Expected line format: `<key-type> <base64-key> [optional-comment]`
/// e.g. `ml-dsa-65 AAAA...base64... user@host`
///
/// Empty lines and lines starting with `#` are skipped.
pub fn parse_authorized_keys(contents: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;

    contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _key_type = parts.next()?; // e.g. "ml-dsa-65"
            let key_data = parts.next()?;  // base64-encoded verifying key
            engine.decode(key_data).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn parse_valid_keys() {
        let engine = base64::engine::general_purpose::STANDARD;
        let key1 = engine.encode(b"fake-key-data-one");
        let key2 = engine.encode(b"fake-key-data-two");

        let contents = format!("ml-dsa-65 {key1} alice@laptop\nml-dsa-65 {key2} bob@desktop\n");
        let keys = parse_authorized_keys(&contents);

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], b"fake-key-data-one");
        assert_eq!(keys[1], b"fake-key-data-two");
    }

    #[test]
    fn parse_key_without_comment() {
        let engine = base64::engine::general_purpose::STANDARD;
        let key = engine.encode(b"fake-key-no-comment");

        let contents = format!("ml-dsa-65 {key}\n");
        let keys = parse_authorized_keys(&contents);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], b"fake-key-no-comment");
    }

    #[test]
    fn skip_comments_and_blanks() {
        let engine = base64::engine::general_purpose::STANDARD;
        let key = engine.encode(b"real-key");

        let contents = format!("# this is a comment\n\n  \nml-dsa-65 {key}\n# another comment\n");
        let keys = parse_authorized_keys(&contents);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], b"real-key");
    }

    #[test]
    fn skip_invalid_base64() {
        let contents = "ml-dsa-65 @@@ not base64 @@@\nml-dsa-65 ~~~\n";
        let keys = parse_authorized_keys(contents);
        assert!(keys.is_empty());
    }

    #[test]
    fn empty_file() {
        let keys = parse_authorized_keys("");
        assert!(keys.is_empty());
    }

    #[test]
    fn load_key_bytes_missing_file() {
        let result = load_key_bytes(Path::new("/nonexistent/path/key"));
        assert!(result.is_err());
    }

    #[test]
    fn load_key_bytes_from_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test_key");
        std::fs::write(&key_path, b"test-key-material").unwrap();

        let bytes = load_key_bytes(&key_path).unwrap();
        assert_eq!(bytes, b"test-key-material");
    }
}
