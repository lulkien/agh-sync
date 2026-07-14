//! Integration tests using wiremock to simulate AdGuardHome instances.
//!
//! Tests the full sync flow: origin → replica with mock HTTP endpoints.

use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agh_sync_core::client::Client;
use agh_sync_core::config::AdGuardInstance;

fn test_instance(url: &str) -> AdGuardInstance {
    AdGuardInstance {
        url: url.to_string(),
        web_url: None,
        api_path: "/control".into(),
        username: Some("admin".into()),
        password: Some("pass".into()),
        cookie: None,
        request_headers: Default::default(),
        insecure_skip_verify: false,
        auto_setup: false,
        interface_name: None,
        dhcp_server_enabled: None,
        config_path: None,
        host: None,
        web_host: None,
    }
}

fn status_json(version: &str, protection: bool) -> serde_json::Value {
    json!({
        "version": version,
        "running": true,
        "protection_enabled": protection,
        "dns_addresses": ["127.0.0.1"],
        "dns_port": 53,
        "http_port": 3000,
        "language": "en"
    })
}

#[tokio::test]
async fn test_client_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_json("v0.107.0", true)))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let status = client.status().await.unwrap();
    assert_eq!(status.version, "v0.107.0");
    assert!(status.running);
    assert!(status.protection_enabled);
}

#[tokio::test]
async fn test_client_auth_failure() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/status"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let result = client.status().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_setup_needed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/status"))
        .respond_with(ResponseTemplate::new(200).set_body_string("install/configure"))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let result = client.status().await;
    assert!(matches!(
        result,
        Err(agh_sync_core::client::ClientError::SetupNeeded)
    ));
}

#[tokio::test]
async fn test_filtering_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/filtering/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "interval": 24,
            "filters": [
                {"url": "https://example.com/filter.txt", "name": "Test Filter", "enabled": true, "id": 1}
            ],
            "whitelist_filters": [],
            "user_rules": ["||blockme.com^"]
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let filters = client.filtering().await.unwrap();
    assert_eq!(filters.enabled, Some(true));
    assert_eq!(filters.interval, Some(24));
    assert_eq!(filters.filters.as_ref().unwrap().len(), 1);
    assert_eq!(
        filters.user_rules.as_deref(),
        Some(vec!["||blockme.com^".to_string()].as_slice())
    );
}

#[tokio::test]
async fn test_rewrite_entries() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/rewrite/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"domain": "a.com", "answer": "1.1.1.1", "enabled": true},
            {"domain": "b.com", "answer": "2.2.2.2", "enabled": false}
        ])))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let entries = client.rewrite_entries().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].domain, "a.com");
    assert_eq!(entries[1].answer, "2.2.2.2");
}

#[tokio::test]
async fn test_clients() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/clients"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "clients": [
                {"name": "laptop", "ids": ["aa:bb:cc:dd:ee:ff"]},
                {"name": "phone", "ids": ["11:22:33:44:55:66"]}
            ]
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let clients = client.clients().await.unwrap();
    assert_eq!(clients.clients.len(), 2);
    assert_eq!(clients.clients[0].name, "laptop");
}

#[tokio::test]
async fn test_dns_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/dns_info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "upstream_dns": ["8.8.8.8", "1.1.1.1"],
            "bootstrap_dns": ["9.9.9.9"],
            "ratelimit": 20,
            "blocking_mode": "default",
            "cache_size": 4194304
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let dns = client.dns_config().await.unwrap();
    assert_eq!(dns.upstream_dns, vec!["8.8.8.8", "1.1.1.1"]);
    assert_eq!(dns.ratelimit, Some(20));
}

#[tokio::test]
async fn test_toggle_protection() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/control/dns_config"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    client.toggle_protection(false).await.unwrap();
}

#[tokio::test]
async fn test_dhcp_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/dhcp/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "interface_name": "eth0",
            "v4": {
                "gateway_ip": "192.168.1.1",
                "subnet_mask": "255.255.255.0",
                "range_start": "192.168.1.100",
                "range_end": "192.168.1.200",
                "lease_duration": 86400
            },
            "static_leases": [
                {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10", "hostname": "server"}
            ]
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let dhcp = client.dhcp_config().await.unwrap();
    assert_eq!(dhcp.enabled, Some(true));
    assert_eq!(dhcp.interface_name.as_deref(), Some("eth0"));
    assert_eq!(dhcp.static_leases.as_ref().unwrap().len(), 1);
}

#[tokio::test]
async fn test_access_list() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/access/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "allowed_clients": ["192.168.1.0/24"],
            "disallowed_clients": ["10.0.0.0/8"],
            "blocked_hosts": ["ads.example.com"]
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let al = client.access_list().await.unwrap();
    assert_eq!(al.allowed_clients, vec!["192.168.1.0/24"]);
    assert_eq!(al.disallowed_clients, vec!["10.0.0.0/8"]);
}

#[tokio::test]
async fn test_safe_search_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/safesearch/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "google": true,
            "bing": true,
            "youtube": false
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let ss = client.safe_search_config().await.unwrap();
    assert_eq!(ss.enabled, Some(true));
    assert_eq!(ss.google, Some(true));
    assert_eq!(ss.youtube, Some(false));
}

#[tokio::test]
async fn test_query_log_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/querylog/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "interval": 90.0,
            "anonymize_client_ip": false,
            "ignored": []
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let qlc = client.query_log_config().await.unwrap();
    assert_eq!(qlc.enabled, Some(true));
    assert_eq!(qlc.interval, Some(90.0));
}

#[tokio::test]
async fn test_stats_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/control/stats/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "interval": 24
        })))
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, None).unwrap();

    let sc = client.stats_config().await.unwrap();
    assert_eq!(sc.interval, Some(24));
}

#[tokio::test]
async fn test_timeout() {
    let server = MockServer::start().await;

    // Set up a mock that delays longer than the timeout
    Mock::given(method("GET"))
        .and(path("/control/status"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(status_json("v0.107.0", true))
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    let inst = test_instance(&server.uri());
    let client = Client::new(&inst, Some(Duration::from_millis(100))).unwrap();

    let result = client.status().await;
    assert!(result.is_err());
}
