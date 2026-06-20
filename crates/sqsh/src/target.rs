use anyhow::{Result, bail};

/// A parsed remote target: optional user, hostname, optional port.
#[derive(Debug, Clone)]
pub struct Target {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl Target {
    /// Parse `[user@]host[:port]`.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            bail!("empty target");
        }

        let (user, rest) = match input.split_once('@') {
            Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
            Some(_) => bail!("empty user in target"),
            None => (None, input),
        };

        // IPv6 literals look like `[::1]:port` — preserve brackets.
        let (host, port) = if let Some(stripped) = rest.strip_prefix('[') {
            let (host, after) = stripped
                .split_once(']')
                .ok_or_else(|| anyhow::anyhow!("unclosed IPv6 bracket"))?;
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or_else(|| anyhow::anyhow!("expected :port after ]"))?
                        .parse()?,
                ),
            };
            (host.to_string(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) if !h.is_empty() => (h.to_string(), Some(p.parse()?)),
                _ => (rest.to_string(), None),
            }
        };

        if host.is_empty() {
            bail!("empty host in target");
        }

        Ok(Self { user, host, port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only() {
        let t = Target::parse("example.com").unwrap();
        assert_eq!(t.user, None);
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, None);
    }

    #[test]
    fn user_at_host() {
        let t = Target::parse("alice@example.com").unwrap();
        assert_eq!(t.user.as_deref(), Some("alice"));
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, None);
    }

    #[test]
    fn host_with_port() {
        let t = Target::parse("example.com:2222").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, Some(2222));
    }

    #[test]
    fn user_host_port() {
        let t = Target::parse("alice@example.com:2222").unwrap();
        assert_eq!(t.user.as_deref(), Some("alice"));
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, Some(2222));
    }

    #[test]
    fn ipv6_with_port() {
        let t = Target::parse("[::1]:2222").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, Some(2222));
    }

    #[test]
    fn ipv6_no_port() {
        let t = Target::parse("[::1]").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, None);
    }

    #[test]
    fn empty_user_rejected() {
        assert!(Target::parse("@host").is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(Target::parse("").is_err());
    }
}
