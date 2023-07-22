use std::sync::OnceLock;

use regex::Regex;

pub fn is_valid_email(addr: &str) -> bool {
    let mut parts = addr.splitn(2, '@');

    let local_part = {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$").unwrap())
    };
    let domain_part = {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"^(?i)[a-z0-9.-]+\.[a-z]{2,}$").unwrap())
    };

    parts
        .next()
        .map(|p| local_part.is_match(p))
        .unwrap_or_default()
        && parts
            .next()
            .map(|p| {
                domain_part.is_match(p)
                    && p.split('.')
                        .all(|p| !p.is_empty() && !p.starts_with('-') && !p.ends_with('-'))
            })
            .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@example.com"));
        assert!(is_valid_email("user+name@example.com"));
        assert!(is_valid_email("user.name+tag@example.co.uk"));
        assert!(is_valid_email("user@example.co.uk"));
        assert!(is_valid_email("user@example.io"));
        assert!(is_valid_email("user@example.travel"));
        assert!(is_valid_email("user@example.museum"));
        assert!(is_valid_email("user@example.name"));
        assert!(is_valid_email("user@example.pro"));
        assert!(is_valid_email("user@example.tel"));
        assert!(is_valid_email("user@example.xxx"));
        assert!(!is_valid_email("user@.example.com"));
        assert!(!is_valid_email("user@example..com"));
        assert!(!is_valid_email("user@example.com."));
        assert!(!is_valid_email("user@-example.com"));
        assert!(!is_valid_email("user@example-.com"));
        assert!(!is_valid_email("user@example.com-"));
        assert!(!is_valid_email("user@example.com:"));
        assert!(!is_valid_email("user@example.com,"));
        assert!(!is_valid_email("user@example.com;"));
        assert!(!is_valid_email("user@example.com'"));
        assert!(!is_valid_email("user@example.com\""));
        assert!(!is_valid_email("user@example.com["));
        assert!(!is_valid_email("user@example.com]"));
        assert!(!is_valid_email("user@example.com("));
        assert!(!is_valid_email("user@example.com)"));
        assert!(!is_valid_email("user@example.com<"));
        assert!(!is_valid_email("user@example.com>"));
        assert!(!is_valid_email("user@example.com\\"));
        assert!(!is_valid_email("user@example.com/"));
        assert!(!is_valid_email("user@example.com "));
        assert!(!is_valid_email("user@example.com\n"));
        assert!(!is_valid_email("user@example.com\t"));
        assert!(!is_valid_email("user@example.com\r"));
        assert!(!is_valid_email("user@example.com\u{200B}"));
        assert!(!is_valid_email("user@example.com\u{FEFF}"));
    }
}
