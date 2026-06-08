//! ACL rule matching engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::db::{
    models::AclRule,
    provider::{DbError, DbProvider},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Default)]
pub struct AclEngine {
    rules: Vec<AclRule>,
}

impl AclEngine {
    pub async fn from_db(db: &dyn DbProvider) -> Result<Self, DbError> {
        let rules = db.get_acl_rules().await?;
        Ok(Self {
            rules: sorted_rules(rules),
        })
    }

    pub fn check_access(
        &self,
        user_id: i64,
        user_group_ids: &[i64],
        target_host: &str,
        target_port: u16,
    ) -> AclDecision {
        evaluate_acl(
            &self.rules,
            user_id,
            user_group_ids,
            target_host,
            target_port,
        )
    }

    pub fn reload(&mut self, rules: Vec<AclRule>) {
        self.rules = sorted_rules(rules);
    }
}

/// Evaluate ACL rules for a user connecting to a target.
/// Higher-priority matching rules win. If no rules match, default deny.
pub fn evaluate_acl(
    rules: &[AclRule],
    user_id: i64,
    user_group_ids: &[i64],
    target_host: &str,
    target_port: u16,
) -> AclDecision {
    rules
        .iter()
        .filter(|rule| rule_matches(rule, user_id, user_group_ids, target_host, target_port))
        .max_by_key(|rule| rule.priority)
        .map(rule_action)
        .unwrap_or(AclDecision::Deny)
}

fn sorted_rules(mut rules: Vec<AclRule>) -> Vec<AclRule> {
    rules.sort_by(|left, right| right.priority.cmp(&left.priority));
    rules
}

fn rule_action(rule: &AclRule) -> AclDecision {
    if rule.action.eq_ignore_ascii_case("allow") {
        AclDecision::Allow
    } else {
        AclDecision::Deny
    }
}

fn rule_matches(
    rule: &AclRule,
    user_id: i64,
    user_group_ids: &[i64],
    target_host: &str,
    target_port: u16,
) -> bool {
    if let Some(rule_user_id) = rule.user_id {
        if rule_user_id != user_id {
            return false;
        }
    }

    if let Some(rule_group_id) = rule.group_id {
        if !user_group_ids.contains(&rule_group_id) {
            return false;
        }
    }

    if let Some(ref pattern) = rule.target_host {
        if !host_matches(pattern, target_host) {
            return false;
        }
    }

    if let Some(rule_port) = rule.target_port {
        if rule_port != i32::from(target_port) {
            return false;
        }
    }

    true
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(cidr) = parse_cidr(pattern) {
        return match host.parse::<IpAddr>() {
            Ok(ip) => cidr.contains(ip),
            Err(_) => false,
        };
    }

    glob_matches(pattern, host)
}

fn glob_matches(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase().into_bytes();
    let candidate = candidate.to_ascii_lowercase().into_bytes();

    let mut pattern_idx = 0usize;
    let mut candidate_idx = 0usize;
    let mut star_idx = None;
    let mut backtrack_idx = 0usize;

    while candidate_idx < candidate.len() {
        if pattern_idx < pattern.len() && pattern[pattern_idx] == candidate[candidate_idx] {
            pattern_idx += 1;
            candidate_idx += 1;
        } else if pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
            star_idx = Some(pattern_idx);
            pattern_idx += 1;
            backtrack_idx = candidate_idx;
        } else if let Some(star) = star_idx {
            pattern_idx = star + 1;
            backtrack_idx += 1;
            candidate_idx = backtrack_idx;
        } else {
            return false;
        }
    }

    while pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                ipv4_to_u32(network) & ipv4_mask(self.prefix_len)
                    == ipv4_to_u32(ip) & ipv4_mask(self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                ipv6_to_u128(network) & ipv6_mask(self.prefix_len)
                    == ipv6_to_u128(ip) & ipv6_mask(self.prefix_len)
            }
            _ => false,
        }
    }
}

fn parse_cidr(pattern: &str) -> Option<Cidr> {
    let (network, prefix_len) = pattern.split_once('/')?;
    let network = network.parse::<IpAddr>().ok()?;
    let prefix_len = prefix_len.parse::<u8>().ok()?;

    let max_prefix = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix_len > max_prefix {
        return None;
    }

    Some(Cidr {
        network,
        prefix_len,
    })
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        models::{Group, Session, User},
        provider::DbError,
    };

    fn rule(
        id: i64,
        priority: i32,
        user_id: Option<i64>,
        group_id: Option<i64>,
        target_host: Option<&str>,
        target_port: Option<i32>,
        action: &str,
    ) -> AclRule {
        AclRule {
            id,
            priority,
            user_id,
            group_id,
            target_host: target_host.map(str::to_owned),
            target_port,
            action: action.to_owned(),
        }
    }

    #[test]
    fn user_specific_rule_matches() {
        let rules = vec![rule(1, 10, Some(42), None, Some("*"), None, "allow")];

        assert_eq!(
            evaluate_acl(&rules, 42, &[], "server.example.com", 3389),
            AclDecision::Allow
        );
        assert_eq!(
            evaluate_acl(&rules, 99, &[], "server.example.com", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn group_based_rule_matches() {
        let rules = vec![rule(1, 10, None, Some(7), Some("*"), None, "allow")];

        assert_eq!(
            evaluate_acl(&rules, 1, &[1, 7, 9], "server.example.com", 3389),
            AclDecision::Allow
        );
        assert_eq!(
            evaluate_acl(&rules, 1, &[1, 9], "server.example.com", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn wildcard_host_patterns_match() {
        assert!(host_matches("*", "anything.example.com"));
        assert!(host_matches("*.example.com", "server.example.com"));
        assert!(host_matches("192.168.*", "192.168.10.25"));
        assert!(!host_matches("*.example.com", "server.other.com"));
        assert!(!host_matches("192.168.*", "192.169.10.25"));
    }

    #[test]
    fn cidr_host_patterns_match() {
        assert!(host_matches("192.168.1.0/24", "192.168.1.42"));
        assert!(!host_matches("192.168.1.0/24", "192.168.2.42"));
        assert!(host_matches("2001:db8::/32", "2001:db8::1"));
        assert!(!host_matches("2001:db8::/32", "2001:db9::1"));
        assert!(!host_matches("192.168.1.0/24", "server.example.com"));
    }

    #[test]
    fn port_matching_is_enforced() {
        let rules = vec![rule(1, 10, None, None, Some("*"), Some(3389), "allow")];

        assert_eq!(
            evaluate_acl(&rules, 1, &[], "server.example.com", 3389),
            AclDecision::Allow
        );
        assert_eq!(
            evaluate_acl(&rules, 1, &[], "server.example.com", 22),
            AclDecision::Deny
        );
    }

    #[test]
    fn higher_priority_rule_wins_even_if_rules_are_unsorted() {
        let rules = vec![
            rule(1, 10, None, None, Some("*"), None, "allow"),
            rule(2, 100, None, None, Some("*"), None, "deny"),
        ];

        assert_eq!(
            evaluate_acl(&rules, 1, &[], "server.example.com", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn defaults_to_deny_when_no_rules_match() {
        let rules = vec![rule(
            1,
            10,
            Some(7),
            None,
            Some("*.example.com"),
            None,
            "allow",
        )];

        assert_eq!(
            evaluate_acl(&rules, 8, &[], "server.other.com", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn mixed_allow_and_deny_rules_follow_priority() {
        let rules = vec![
            rule(1, 100, None, None, Some("prod-*"), None, "deny"),
            rule(
                2,
                200,
                Some(42),
                None,
                Some("prod-admin"),
                Some(3389),
                "allow",
            ),
            rule(3, 150, None, Some(5), Some("prod-*"), Some(3389), "allow"),
        ];

        assert_eq!(
            evaluate_acl(&rules, 7, &[5], "prod-app", 3389),
            AclDecision::Allow
        );
        assert_eq!(
            evaluate_acl(&rules, 42, &[], "prod-admin", 3389),
            AclDecision::Allow
        );
        assert_eq!(
            evaluate_acl(&rules, 7, &[5], "prod-app", 22),
            AclDecision::Deny
        );
        assert_eq!(
            evaluate_acl(&rules, 8, &[], "prod-app", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn combined_user_and_group_constraints_are_both_required() {
        let rules = vec![rule(
            1,
            10,
            Some(42),
            Some(7),
            Some("*.example.com"),
            None,
            "allow",
        )];

        assert_eq!(
            evaluate_acl(&rules, 42, &[7], "host.example.com", 3389),
            AclDecision::Allow
        );
        assert_eq!(
            evaluate_acl(&rules, 42, &[8], "host.example.com", 3389),
            AclDecision::Deny
        );
    }

    struct MockDbProvider {
        rules: Vec<AclRule>,
    }

    #[async_trait::async_trait]
    impl DbProvider for MockDbProvider {
        async fn migrate(&self) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn get_user_by_username(&self, _username: &str) -> Result<Option<User>, DbError> {
            unimplemented!()
        }

        async fn create_user(&self, _username: &str, _nt_hash: &[u8]) -> Result<User, DbError> {
            unimplemented!()
        }

        async fn list_users(&self) -> Result<Vec<User>, DbError> {
            unimplemented!()
        }

        async fn set_user_enabled(&self, _user_id: i64, _enabled: bool) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn get_user_groups(&self, _user_id: i64) -> Result<Vec<Group>, DbError> {
            unimplemented!()
        }

        async fn create_group(&self, _name: &str) -> Result<Group, DbError> {
            unimplemented!()
        }

        async fn add_user_to_group(&self, _user_id: i64, _group_id: i64) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn get_acl_rules(&self) -> Result<Vec<AclRule>, DbError> {
            Ok(self.rules.clone())
        }

        async fn create_acl_rule(&self, _rule: &AclRule) -> Result<AclRule, DbError> {
            unimplemented!()
        }

        async fn create_session(&self, _session: &Session) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn end_session(&self, _session_id: &str) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn get_active_sessions(&self) -> Result<Vec<Session>, DbError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn acl_engine_loads_and_reloads_rules() {
        let db = MockDbProvider {
            rules: vec![
                rule(1, 10, None, None, Some("*"), None, "allow"),
                rule(2, 100, None, None, Some("secret-*"), None, "deny"),
            ],
        };

        let mut engine = AclEngine::from_db(&db).await.expect("load rules");

        assert_eq!(
            engine.check_access(1, &[], "secret-host", 3389),
            AclDecision::Deny
        );
        assert_eq!(
            engine.check_access(1, &[], "public-host", 3389),
            AclDecision::Allow
        );

        engine.reload(vec![rule(3, 50, None, None, Some("*"), None, "deny")]);

        assert_eq!(
            engine.check_access(1, &[], "public-host", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn empty_rules_default_deny() {
        let rules: Vec<AclRule> = vec![];
        assert_eq!(
            evaluate_acl(&rules, 1, &[1], "anything", 3389),
            AclDecision::Deny
        );
    }

    #[test]
    fn cidr_slash_zero_matches_all() {
        assert!(host_matches("0.0.0.0/0", "192.168.1.1"));
        assert!(host_matches("0.0.0.0/0", "10.0.0.1"));
    }

    #[test]
    fn cidr_slash_32_matches_exact() {
        assert!(host_matches("10.0.0.5/32", "10.0.0.5"));
        assert!(!host_matches("10.0.0.5/32", "10.0.0.6"));
    }

    #[test]
    fn glob_case_insensitive() {
        assert!(host_matches("*.EXAMPLE.COM", "server.example.com"));
        assert!(host_matches("*.example.com", "SERVER.EXAMPLE.COM"));
    }

    #[test]
    fn glob_multiple_wildcards() {
        assert!(host_matches("*prod*db*", "us-prod-mysql-db-01"));
        assert!(!host_matches("*prod*db*", "us-staging-mysql-01"));
    }

    #[test]
    fn invalid_cidr_prefix_rejected() {
        // /33 is invalid for IPv4
        assert!(parse_cidr("192.168.1.0/33").is_none());
        // /129 is invalid for IPv6
        assert!(parse_cidr("::1/129").is_none());
    }

    #[test]
    fn non_ip_host_not_matched_by_cidr() {
        assert!(!host_matches("10.0.0.0/8", "hostname-10.internal"));
    }
}
