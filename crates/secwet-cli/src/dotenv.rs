//! Dotenv (.env) format parser for Secwet.
//!
//! Handles comments (`#`), optional `export` prefix, single and double quotes,
//! escape sequences in double quotes (`\n`, `\t`, `\r`, `\"`, `\\`), and multiline values.

/// Parses dotenv-formatted text into key-value pairs.
pub fn parse_dotenv(input: &str) -> Result<Vec<(String, String)>, String> {
    let mut results = Vec::new();
    let mut chars = input.chars().peekable();

    while chars.peek().is_some() {
        // Skip leading whitespace (spaces, tabs, newlines)
        while let Some(&c) = chars.peek() {
            if c == '\r' || c == '\n' || c == ' ' || c == '\t' {
                chars.next();
            } else {
                break;
            }
        }

        if chars.peek().is_none() {
            break;
        }

        // Comment line starting with '#'
        if chars.peek() == Some(&'#') {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }

        // Parse key up to '='
        let mut key_part = String::new();
        let mut found_eq = false;
        while let Some(&c) = chars.peek() {
            if c == '=' {
                chars.next();
                found_eq = true;
                break;
            }
            if c == '\n' {
                chars.next();
                break;
            }
            key_part.push(c);
            chars.next();
        }

        let key_trimmed = key_part.trim();
        if key_trimmed.is_empty() {
            continue;
        }

        if !found_eq {
            return Err(format!("invalid line: expected '=' in '{key_trimmed}'"));
        }

        // Strip optional `export ` prefix
        let key = if let Some(stripped) = key_trimmed.strip_prefix("export ") {
            stripped.trim()
        } else if let Some(stripped) = key_trimmed.strip_prefix("export\t") {
            stripped.trim()
        } else {
            key_trimmed
        };

        secwet_proto::validate_secret_name(key)
            .map_err(|e| format!("invalid secret name '{key}': {e}"))?;

        // Skip horizontal whitespace after '='
        while let Some(&c) = chars.peek() {
            if c == ' ' || c == '\t' {
                chars.next();
            } else {
                break;
            }
        }

        // Parse value
        let value = match chars.peek() {
            Some(&'"') => {
                chars.next(); // consume opening quote
                let mut val = String::new();
                let mut closed = false;
                #[allow(clippy::while_let_on_iterator)]
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        match chars.next() {
                            Some('n') => val.push('\n'),
                            Some('r') => val.push('\r'),
                            Some('t') => val.push('\t'),
                            Some('"') => val.push('"'),
                            Some('\\') => val.push('\\'),
                            Some(other) => {
                                val.push('\\');
                                val.push(other);
                            }
                            None => val.push('\\'),
                        }
                    } else if c == '"' {
                        closed = true;
                        break;
                    } else {
                        val.push(c);
                    }
                }
                if !closed {
                    return Err(format!("unclosed double quote for key '{key}'"));
                }
                // Skip any trailing inline comment on the same line
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                val
            }
            Some(&'\'') => {
                chars.next(); // consume opening quote
                let mut val = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '\'' {
                        closed = true;
                        break;
                    } else {
                        val.push(c);
                    }
                }
                if !closed {
                    return Err(format!("unclosed single quote for key '{key}'"));
                }
                // Skip any trailing inline comment on the same line
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                val
            }
            _ => {
                // Unquoted value: read until newline or unquoted inline '#' comment
                let mut raw = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '\n' {
                        chars.next();
                        break;
                    }
                    if c == '#' && (raw.ends_with(' ') || raw.ends_with('\t')) {
                        // Skip the rest of the line
                        for nc in chars.by_ref() {
                            if nc == '\n' {
                                break;
                            }
                        }
                        break;
                    }
                    raw.push(c);
                    chars.next();
                }
                raw.trim().to_string()
            }
        };

        secwet_proto::validate_secret_value(&value)
            .map_err(|e| format!("invalid secret value for '{key}': {e}"))?;

        results.push((key.to_string(), value));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv_basic() {
        let input = r#"
# Comment line
PORT=8080
DATABASE_URL="postgres://user:pass@localhost/db?ssl=true"
SINGLE_QUOTED='raw value with spaces'
export API_TOKEN=xyz123
ESCAPED_NEWLINE="line1\nline2\ttab"
"#;
        let pairs = parse_dotenv(input).unwrap();
        assert_eq!(pairs.len(), 5);
        assert_eq!(pairs[0], ("PORT".to_string(), "8080".to_string()));
        assert_eq!(
            pairs[1],
            (
                "DATABASE_URL".to_string(),
                "postgres://user:pass@localhost/db?ssl=true".to_string()
            )
        );
        assert_eq!(
            pairs[2],
            (
                "SINGLE_QUOTED".to_string(),
                "raw value with spaces".to_string()
            )
        );
        assert_eq!(pairs[3], ("API_TOKEN".to_string(), "xyz123".to_string()));
        assert_eq!(
            pairs[4],
            (
                "ESCAPED_NEWLINE".to_string(),
                "line1\nline2\ttab".to_string()
            )
        );
    }

    #[test]
    fn test_parse_dotenv_multiline_quotes() {
        let input = r#"
RSA_KEY="-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----"
"#;
        let pairs = parse_dotenv(input).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "RSA_KEY");
        assert!(pairs[0].1.contains("BEGIN CERTIFICATE"));
        assert!(pairs[0].1.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_parse_dotenv_inline_comment() {
        let input = "DEBUG=true # this is a comment\n";
        let pairs = parse_dotenv(input).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("DEBUG".to_string(), "true".to_string()));
    }

    #[test]
    fn test_parse_dotenv_invalid_name() {
        let input = "123INVALID=value\n";
        assert!(parse_dotenv(input).is_err());
    }
}
