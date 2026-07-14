//! Merge/diff logic for API model types.

use crate::model::{ClientSettings, DhcpStaticLease, Filter, RewriteEntry};

/// Merge rewrite entries: returns (to_add, to_remove, to_update, duplicates).
pub fn merge_rewrite_entries(
    current: &[RewriteEntry],
    desired: &[RewriteEntry],
) -> (
    Vec<RewriteEntry>,
    Vec<RewriteEntry>,
    Vec<RewriteEntry>,
    Vec<RewriteEntry>,
) {
    let current_set: std::collections::HashSet<_> =
        current.iter().map(|e| (&e.domain, &e.answer)).collect();
    let desired_set: std::collections::HashSet<_> =
        desired.iter().map(|e| (&e.domain, &e.answer)).collect();

    let removes: Vec<_> = current
        .iter()
        .filter(|e| !desired_set.contains(&(&e.domain, &e.answer)))
        .cloned()
        .collect();

    let adds: Vec<_> = desired
        .iter()
        .filter(|e| !current_set.contains(&(&e.domain, &e.answer)))
        .cloned()
        .collect();

    (adds, removes, vec![], vec![])
}

/// Merge filters: returns (to_add, to_update, to_delete).
pub fn merge_filters(
    current: Option<&Vec<Filter>>,
    desired: Option<&Vec<Filter>>,
) -> (Vec<Filter>, Vec<Filter>, Vec<Filter>) {
    let cur = current.map(|f| f.as_slice()).unwrap_or(&[]);
    let des = desired.map(|f| f.as_slice()).unwrap_or(&[]);

    let cur_urls: std::collections::HashSet<_> = cur.iter().map(|f| &f.url).collect();
    let des_urls: std::collections::HashSet<_> = des.iter().map(|f| &f.url).collect();

    let deletes: Vec<_> = cur
        .iter()
        .filter(|f| !des_urls.contains(&f.url))
        .cloned()
        .collect();
    let adds: Vec<_> = des
        .iter()
        .filter(|f| !cur_urls.contains(&f.url))
        .cloned()
        .collect();

    (adds, vec![], deletes)
}

/// Merge client settings: returns (to_add, to_update, to_delete).
pub fn merge_clients(
    current: &[ClientSettings],
    desired: &[ClientSettings],
) -> (
    Vec<ClientSettings>,
    Vec<ClientSettings>,
    Vec<ClientSettings>,
) {
    let cur_names: std::collections::HashSet<_> = current.iter().map(|c| &c.name).collect();
    let des_names: std::collections::HashSet<_> = desired.iter().map(|c| &c.name).collect();

    let deletes: Vec<_> = current
        .iter()
        .filter(|c| !des_names.contains(&c.name))
        .cloned()
        .collect();
    let adds: Vec<_> = desired
        .iter()
        .filter(|c| !cur_names.contains(&c.name))
        .cloned()
        .collect();
    let updates: Vec<_> = desired
        .iter()
        .filter(|c| cur_names.contains(&c.name))
        .cloned()
        .collect();

    (adds, updates, deletes)
}

/// Merge DHCP static leases: returns (to_add, to_remove).
pub fn merge_dhcp_leases(
    current: Option<&Vec<DhcpStaticLease>>,
    desired: Option<&Vec<DhcpStaticLease>>,
) -> (Vec<DhcpStaticLease>, Vec<DhcpStaticLease>) {
    let cur = current.map(|l| l.as_slice()).unwrap_or(&[]);
    let des = desired.map(|l| l.as_slice()).unwrap_or(&[]);

    let cur_macs: std::collections::HashSet<_> = cur.iter().map(|l| &l.mac).collect();
    let des_macs: std::collections::HashSet<_> = des.iter().map(|l| &l.mac).collect();

    let removes: Vec<_> = cur
        .iter()
        .filter(|l| !des_macs.contains(&l.mac))
        .cloned()
        .collect();
    let adds: Vec<_> = des
        .iter()
        .filter(|l| !cur_macs.contains(&l.mac))
        .cloned()
        .collect();

    (adds, removes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(domain: &str, answer: &str) -> RewriteEntry {
        RewriteEntry {
            domain: domain.into(),
            answer: answer.into(),
            enabled: true,
        }
    }

    fn flt(url: &str, name: &str) -> Filter {
        Filter {
            url: url.into(),
            name: name.into(),
            enabled: true,
            id: 0,
        }
    }

    fn cli(name: &str) -> ClientSettings {
        ClientSettings {
            name: name.into(),
            ids: vec![],
            use_global_settings: false,
            use_global_blocked_services: false,
            filtering_enabled: None,
            parental_enabled: None,
            safebrowsing_enabled: None,
            safesearch_enabled: None,
            tags: vec![],
        }
    }

    fn lease(mac: &str, ip: &str, hostname: &str) -> DhcpStaticLease {
        DhcpStaticLease {
            mac: mac.into(),
            ip: ip.into(),
            hostname: hostname.into(),
        }
    }

    #[test]
    fn merge_rewrites_add_only() {
        let desired = vec![re("a.com", "1.1.1.1"), re("b.com", "2.2.2.2")];
        let (adds, removes, _, _) = merge_rewrite_entries(&[], &desired);
        assert_eq!(adds.len(), 2);
        assert!(removes.is_empty());
    }

    #[test]
    fn merge_rewrites_remove_only() {
        let current = vec![re("a.com", "1.1.1.1")];
        let (adds, removes, _, _) = merge_rewrite_entries(&current, &[]);
        assert!(adds.is_empty());
        assert_eq!(removes.len(), 1);
    }

    #[test]
    fn merge_rewrites_noop() {
        let current = vec![re("a.com", "1.1.1.1")];
        let desired = vec![re("a.com", "1.1.1.1")];
        let (adds, removes, _, _) = merge_rewrite_entries(&current, &desired);
        assert!(adds.is_empty());
        assert!(removes.is_empty());
    }

    #[test]
    fn merge_rewrites_add_and_remove() {
        let current = vec![re("a.com", "1.1.1.1"), re("b.com", "2.2.2.2")];
        let desired = vec![re("a.com", "1.1.1.1"), re("c.com", "3.3.3.3")];
        let (adds, removes, _, _) = merge_rewrite_entries(&current, &desired);
        assert_eq!(adds.len(), 1);
        assert_eq!(adds[0].domain, "c.com");
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].domain, "b.com");
    }

    #[test]
    fn merge_filters_add() {
        let desired = vec![flt("http://a.list", "List A")];
        let (adds, _, deletes) = merge_filters(None, Some(&desired));
        assert_eq!(adds.len(), 1);
        assert!(deletes.is_empty());
    }

    #[test]
    fn merge_filters_delete() {
        let current = vec![flt("http://old.list", "Old List")];
        let (adds, _, deletes) = merge_filters(Some(&current), Some(&vec![]));
        assert!(adds.is_empty());
        assert_eq!(deletes.len(), 1);
    }

    #[test]
    fn merge_filters_noop() {
        let filters = vec![flt("http://a.list", "List A")];
        let (adds, _, deletes) = merge_filters(Some(&filters), Some(&filters));
        assert!(adds.is_empty());
        assert!(deletes.is_empty());
    }

    #[test]
    fn merge_clients_add_update_delete() {
        let current = vec![cli("old-client"), cli("changed-client")];
        let desired = vec![cli("changed-client"), cli("new-client")];
        let (adds, updates, deletes) = merge_clients(&current, &desired);
        assert_eq!(adds.len(), 1);
        assert_eq!(adds[0].name, "new-client");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "changed-client");
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].name, "old-client");
    }

    #[test]
    fn merge_clients_empty() {
        let (adds, updates, deletes) = merge_clients(&[], &[]);
        assert!(adds.is_empty());
        assert!(updates.is_empty());
        assert!(deletes.is_empty());
    }

    #[test]
    fn merge_dhcp_leases_add_remove() {
        let current = vec![lease("aa:bb", "10.0.0.1", "old-host")];
        let desired = vec![lease("cc:dd", "10.0.0.2", "new-host")];
        let (adds, removes) = merge_dhcp_leases(Some(&current), Some(&desired));
        assert_eq!(adds.len(), 1);
        assert_eq!(adds[0].mac, "cc:dd");
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].mac, "aa:bb");
    }

    #[test]
    fn merge_dhcp_leases_noop() {
        let leases = vec![lease("aa:bb", "10.0.0.1", "host")];
        let (adds, removes) = merge_dhcp_leases(Some(&leases), Some(&leases));
        assert!(adds.is_empty());
        assert!(removes.is_empty());
    }

    #[test]
    fn merge_dhcp_leases_none() {
        let (adds, removes) = merge_dhcp_leases(None, None);
        assert!(adds.is_empty());
        assert!(removes.is_empty());
    }
}
