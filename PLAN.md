# agh-sync — Rust Rewrite Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Rewrite adguardhome-sync (Go, 22.5K LOC) in Rust as a CLI tool that synchronizes AdGuardHome config from an origin instance to one or more replica instances.

**Architecture:** Tokio async runtime, reqwest HTTP client, axum web server, serde for config/models, tracing for logging, clap for CLI.

**Tech Stack:** Rust 2024 stable, tokio, reqwest, axum, serde + serde_yaml, figment, clap, tracing, prometheus, askama, tokio-cron-scheduler.

---

## Feasibility Analysis Summary

| Source Layer | Go LOC (hand-written) | Generated | Rust ~LOC | Effort |
|---|---|---|---|---|
| CLI entry | 7 | 0 | 20 | minimal |
| Config (YAML+env+flags) | ~800 | 0 | ~400 | 1 day |
| Types (Config, Features) | ~600 | 225 (deepcopy) | ~300 | 0.5 day |
| REST Client (30+ endpoints) | ~1,000 | 0 | ~800 | 1.5 days |
| Client Models (merge/diff) | ~500 | 12,000 (oapi-codegen) | ~600 | 1 day |
| Sync engine + Actions | ~1,100 | 0 | ~800 | 1.5 days |
| HTTP API (status dashboard) | ~220 + 80 (static) | 0 | ~400 | 1 day |
| Metrics (Prometheus) | ~300 | 0 | ~200 | 0.5 day |
| **TOTAL** | **~4,600** | **~13,000** | **~3,500** | **~7 days** |

**Verdict: YES.** No blockers. All dependencies have mature Rust crates. The 13K generated oapi-codegen models collapse to ~500 lines of serde derives.

---

## Task List

### Phase 1: Project Scaffold

#### Task 1.1: Initialize Cargo workspace
```
cargo init agh-sync
```
Set edition = "2024", add dependencies: tokio, clap, serde, serde_yaml, serde_json, reqwest, axum, tracing, tracing-subscriber, figment, prometheus, askama, tokio-cron-scheduler, url, chrono.

Cargo.toml with workspace structure:
- agh-sync (binary)
- agh-sync-core (library — types, client, sync engine)

#### Task 1.2: Set up tracing/logging
Initialize tracing-subscriber with env-filter. `RUST_LOG` env var. Console output default, JSON optional.

### Phase 2: Config & Types

#### Task 2.1: Define config types (agh-sync-core/src/config.rs)
Port types.Config, types.AdGuardInstance, types.API, types.Features, types.FiltersType, types.DNS, types.DHCP, types.Metrics, types.TLS.
All serde Deserialize. FiltersType custom deserializer (bool → all sub-fields, or struct).
No `*bool` → Option<bool>. No nil pointer issues.

#### Task 2.2: Config loading (agh-sync-core/src/config/loader.rs)
Figment-based layered config:
1. Default values (RunOnStart=true, APIPath="/control", API port=8080)
2. YAML file (~/.adguardhome-sync.yaml or --config path)
3. Environment variables (ORIGIN_URL, REPLICA1_URL, etc.)
4. CLI flags (clap)

Replica env parsing: scan env for `REPLICA\d+_URL` pattern, group by index.

#### Task 2.3: Config validation (agh-sync-core/src/config/validate.rs)
- Origin URL required
- At least one replica required
- Cannot mix `replica` (singular) and `replicas` (list)
- Parse ClientTimeout string to Duration
- Init AdGuardInstance (parse URL, set Host/WebHost)

#### Task 2.4: Config printing (agh-sync-core/src/config/print.rs)
`--print-config-only` flag: print masked config and exit. Mask usernames/passwords.

### Phase 3: REST Client

#### Task 3.1: Client trait and struct (agh-sync-core/src/client/mod.rs)
Define `Client` trait with all AGH API methods (~30 methods):
- Status, Stats, QueryLog
- RewriteEntries (list/add/delete/update), RewriteSettings (get/set)
- Filtering (status/add/delete/update/refresh), ToggleFiltering, SetCustomRules
- SafeBrowsing, Parental, SafeSearchConfig
- BlockedServicesSchedule (get/set)
- Clients (list/add/update/delete)
- QueryLogConfig, StatsConfig
- AccessList (get/set)
- DNSConfig (get/set)
- DhcpConfig (get/set), AddDHCPStaticLease, DeleteDHCPStaticLease
- TLSConfig (get/set)
- Setup (auto-setup new instances)
- ToggleProtection
- ProfileInfo (get/set)

#### Task 3.2: Reqwest client implementation (agh-sync-core/src/client/reqwest.rs)
Build reqwest::Client with:
- Base URL = URL + APIPath
- TLS config (insecure skip verify option)
- Auth: cookie (split on `=`) OR basic auth (username:password)
- Request headers map
- Redirect policy (configurable via REDIRECT_POLICY_NO_OF_REDIRECTS env, default: no redirect)
- Timeout

Helper: generic GET that deserializes JSON response, POST/PUT with body.

#### Task 3.3: API model types (agh-sync-core/src/model/mod.rs)
All AGH API response/request types. Serde Deserialize/Serialize.
Key types: ServerStatus, FilterStatus, Filter, RewriteEntry, RewriteSettings, BlockedServicesSchedule, Client, QueryLogConfig, StatsConfig, AccessList, DNSConfig, DhcpStatus, DhcpStaticLease, TlsConfig, SafeSearchConfig, ProfileInfo, Stats, QueryLog.

Also: request types (AddUrlRequest, RemoveUrlRequest, FilterSetUrl, etc.).

### Phase 4: Sync Engine

#### Task 4.1: Sync orchestrator (agh-sync-core/src/sync/mod.rs)
`Sync` function:
1. Validate config (origin URL, replicas present)
2. Log version/build/os/arch
3. Create origin client, fetch all data into `OriginData` struct
4. For each unique replica: call `sync_to(replica)`

Version check: origin and replica AGH version >= MinAgh.

#### Task 4.2: Origin data fetching (agh-sync-core/src/sync/origin.rs)
Sequentially fetch from origin:
- Status → version check
- ProfileInfo
- Parental status
- SafeSearchConfig
- SafeBrowsing status
- RewriteSettings + RewriteEntries
- BlockedServicesSchedule
- Filtering status (Filters + WhitelistFilters + UserRules)
- Clients
- QueryLogConfig
- StatsConfig
- AccessList
- DNSConfig
- DhcpConfig (if DHCP features enabled)
- TLSConfig (if TLS feature enabled)

#### Task 4.3: Replica sync (agh-sync-core/src/sync/replica.rs)
For each replica:
1. Create replica client
2. Get replica status (auto-setup if needed)
3. Version check
4. Run each enabled action:
   - Profile info (theme sync)
   - Protection status
   - Parental, SafeSearch, SafeBrowsing
   - DNS server config
   - Query log config
   - Stats config
   - DNS rewrite settings + entries
   - Filters (blacklist/whitelist/user rules)
   - Blocked services schedule
   - Client settings
   - DNS access lists
   - DHCP server config + static leases
   - TLS config

Reconcile pattern: fetch replica state → compare → push diff.
Merge logic: add new, update changed, delete removed. Skip duplicates.

#### Task 4.4: Merge/diff logic (agh-sync-core/src/model/merge.rs)
Port from Go model-functions.go:
- MergeFilters (add/update/delete filter lists)
- MergeDhcpStaticLeases
- RewriteEntries::merge
- Clients::merge
- Equals methods for config comparison

### Phase 5: HTTP API Server

#### Task 5.1: Axum web server (agh-sync/src/server.rs)
Axum router with:
- GET/POST `/api/v1/sync` — trigger sync
- GET `/api/v1/status` — JSON status
- GET `/api/v1/logs` — recent logs (ring buffer)
- POST `/api/v1/clear-logs`
- GET `/healthz` — health check (origin + all replicas success)
- GET `/metrics` — Prometheus endpoint (if enabled)
- GET `/` — dashboard HTML

Basic auth middleware (optional, from config).
TLS support (optional, from config).

#### Task 5.2: Status dashboard (agh-sync/src/templates/)
Askama template for `index.html`. Port existing Go template.
Embed static assets: favicon.ico, logo.svg, bootstrap CSS/JS, jquery, popper, chart.js.

#### Task 5.3: Graceful shutdown
Signal handling (SIGINT, SIGTERM). Stop cron, drain HTTP connections, exit.

### Phase 6: Metrics

#### Task 6.1: Prometheus metrics (agh-sync-core/src/metrics.rs)
Port from Go metrics.go:
- adguard_avg_processing_time
- adguard_num_dns_queries
- adguard_num_blocked_filtering
- adguard_num_replaced_parental
- adguard_num_replaced_safebrowsing
- adguard_num_replaced_safesearch
- adguard_top_queried_domains
- adguard_top_blocked_domains
- adguard_top_clients
- adguard_query_types
- adguard_running
- adguard_protection_enabled
- adguard_home_sync_sync_duration_seconds
- adguard_home_sync_sync_successful

Scraping loop: periodic fetch from all instances, update gauges.

### Phase 7: CLI

#### Task 7.1: Clap CLI (agh-sync/src/main.rs)
```
agh-sync run [OPTIONS]
  --config <FILE>
  --cron <EXPR>
  --run-on-start
  --print-config-only
  --continue-on-error
  --api-port <PORT>
  --api-username <USER>
  --api-password <PASS>
  ... (all feature flags, origin/replica URL/auth flags)
```

#### Task 7.2: Cron mode
If `--cron` set: parse expression, schedule sync jobs. If API port also set: start server + cron + optional run-on-start. If no API: run cron loop (blocking).

### Phase 8: Tests

#### Task 8.1: Unit tests
- Config parsing from YAML, env, flags
- FiltersType bool/struct deserialization
- Client URL construction, auth header
- Merge logic (filters, clients, rewrites, DHCP leases)
- Feature flag action selection
- Mask function

#### Task 8.2: Integration tests
Mock AGH HTTP server (axum test server or wiremock). Test:
- Full sync flow: origin data → reconcile → replica API calls
- Auto-setup flow
- Continue-on-error behavior
- Unique replica deduplication

### Phase 9: Polish

#### Task 9.1: Docker support
Multi-stage Dockerfile. Static musl build.

#### Task 9.2: CI
GitHub Actions: build, test, clippy, rustfmt check.

---

## Key Rust Crate Mapping

| Go Dependency | Rust Replacement |
|---|---|
| spf13/cobra | clap (derive) |
| caarlos0/env | figment (env provider) |
| go-resty/resty | reqwest |
| gin-gonic/gin | axum |
| robfig/cron | tokio-cron-scheduler |
| uber-go/zap | tracing + tracing-subscriber |
| prometheus/client_golang | prometheus |
| gopkg.in/yaml.v3 | serde_yaml |
| jinzhu/copier | Clone derive / manual |
| oapi-codegen (12K gen) | serde derive (~500 LOC) |
| go-faker/faker | fake crate |
| google/go-cmp | pretty_assertions |
| go.uber.org/mock | mockall |
| html/template | askama |

## What Disappears

- **12K generated code** → serde derives. The OpenAPI-generated client/server models compress entirely.
- **nil pointer checks** → Option<T>. Every `*bool`, `*string`, `*int` in Go becomes `Option<bool>` in Rust. Cleaner, safer.
- **DeepCopy** → Clone derive. The 225-line zz_generated.deepcopy.go vanishes.
- **Interface bloat comment** → Rust traits are the norm, not a lint exception.
- **Mask/manual clone** → derive macros handle it.
- **Global loggers** → tracing spans carry context.

## What Gets Better

- **Startup time**: sub-millisecond vs Go's ~50ms
- **Binary size**: feasible to statically link musl → single ~8MB binary
- **Memory**: no GC pauses during sync
- **Type safety**: serde catches config errors at parse time, not runtime
- **Async**: tokio's cooperative scheduling vs goroutine pool
