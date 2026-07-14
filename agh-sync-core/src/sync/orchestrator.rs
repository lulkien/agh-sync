1|//! Sync orchestrator — fetch from origin, reconcile, push to replicas.
2|
3|use std::time::Instant;
4|
5|use tracing::{error, info};
6|
7|use crate::client::{Client, ClientError};
8|use crate::config::{AdGuardInstance, Config};
9|use crate::model::{
10|    AccessList, BlockedServicesSchedule, Clients, DnsConfig, DhcpStatus,
11|    Filter, FilterStatus, QueryLogConfig, RewriteEntry,
12|    SafeSearchConfig, TlsConfig,
13|};
14|
15|use super::actions;
16|
17|/// All data fetched from the origin instance.
18|pub(crate) struct OriginData {
19|    pub status: ServerStatus,
20|    pub profile_info: Option<ProfileInfo>,
21|    pub parental: bool,
22|    pub safe_search: SafeSearchConfig,
23|    pub safe_browsing: bool,
24|    pub rewrite_settings: RewriteSettings,
25|    pub rewrite_entries: Vec<RewriteEntry>,
26|    pub blocked_services_schedule: BlockedServicesSchedule,
27|    pub filters: FilterStatus,
28|    pub clients: Clients,
29|    pub query_log_config: QueryLogConfig,
30|    pub stats_config: StatsConfig,
31|    pub access_list: AccessList,
32|    pub dns_config: DnsConfig,
33|    pub dhcp_server_config: Option<DhcpStatus>,
34|    pub tls_config: Option<TlsConfig>,
35|}
36|
37|/// Context passed to each sync action.
38|pub(crate) struct ActionContext<'a> {
39|    pub features: &'a Features,
40|    pub continue_on_error: bool,
41|    pub replica: &'a AdGuardInstance,
42|}
43|
44|/// Run a full sync from origin to all replicas.
45|pub async fn sync(cfg: &Config) -> Result<(), String> {
46|    if cfg.origin.url.is_empty() {
47|        return Err("origin URL is required".to_string());
48|    }
49|
50|    let replicas = cfg.unique_replicas();
51|    if replicas.is_empty() {
52|        return Err("no replicas configured".to_string());
53|    }
54|
55|    info!(
56|        version = crate::VERSION,
57|        os = std::env::consts::OS,
58|        arch = std::env::consts::ARCH,
59|        "AdGuardHome sync"
60|    );
61|
62|    // Parse client timeout
63|    let timeout = parse_timeout(cfg.client_timeout.as_deref());
64|
65|    // Create origin client
66|    let origin_client = Client::new(&cfg.origin, timeout).map_err(|e| e.to_string())?;
67|
68|    // Fetch all data from origin
69|    let origin_data = fetch_origin_data(&origin_client, &cfg.features).await?;
70|
71|    // Sync to each replica
72|    for replica in &replicas {
73|        if let Err(e) = sync_to_replica(cfg, replica, &origin_data, timeout).await {
74|            error!(
75|                replica = %replica.url,
76|                error = %e,
77|                "Failed to sync to replica"
78|            );
79|            if !cfg.continue_on_error {
80|                return Err(e);
81|            }
82|        }
83|    }
84|
85|    Ok(())
86|}
87|
88|/// Fetch all relevant data from the origin instance.
89|async fn fetch_origin_data(
90|    client: &Client,
91|    features: &Features,
92|) -> Result<OriginData, String> {
93|    let host = client.host().to_string();
94|
95|    let status = client.status().await.map_err(|e| {
96|        format!("error getting origin status from {host}: {e}")
97|    })?;
98|
99|    info!(version = %status.version, "Connected to origin");
100|
101|    let profile_info = match client.profile_info().await {
102|        Ok(p) => Some(p),
103|        Err(ClientError::SetupNeeded) => None,
104|        Err(e) => {
105|            return Err(format!("error getting profile info: {e}"));
106|        }
107|    };
108|
109|    let parental = client.parental().await.map_err(|e| {
110|        format!("error getting parental status: {e}")
111|    })?;
112|
113|    let safe_search = client.safe_search_config().await.map_err(|e| {
114|        format!("error getting safe search config: {e}")
115|    })?;
116|
117|    let safe_browsing = client.safe_browsing().await.map_err(|e| {
118|        format!("error getting safe browsing status: {e}")
119|    })?;
120|
121|    let rewrite_settings = client.rewrite_settings().await.map_err(|e| {
122|        format!("error getting rewrite settings: {e}")
123|    })?;
124|
125|    let rewrite_entries = client.rewrite_entries().await.map_err(|e| {
126|        format!("error getting rewrite entries: {e}")
127|    })?;
128|
129|    let blocked_services_schedule = client.blocked_services_schedule().await.map_err(|e| {
130|        format!("error getting blocked services schedule: {e}")
131|    })?;
132|
133|    let filters = client.filtering().await.map_err(|e| {
134|        format!("error getting filters: {e}")
135|    })?;
136|
137|    let clients = client.clients().await.map_err(|e| {
138|        format!("error getting clients: {e}")
139|    })?;
140|
141|    let query_log_config = client.query_log_config().await.map_err(|e| {
142|        format!("error getting query log config: {e}")
143|    })?;
144|
145|    let stats_config = client.stats_config().await.map_err(|e| {
146|        format!("error getting stats config: {e}")
147|    })?;
148|
149|    let access_list = client.access_list().await.map_err(|e| {
150|        format!("error getting access list: {e}")
151|    })?;
152|
153|    let dns_config = client.dns_config().await.map_err(|e| {
154|        format!("error getting DNS config: {e}")
155|    })?;
156|
157|    let dhcp_server_config = if features.dhcp.server_config || features.dhcp.static_leases {
158|        Some(client.dhcp_config().await.map_err(|e| {
159|            format!("error getting DHCP config: {e}")
160|        })?)
161|    } else {
162|        None
163|    };
164|
165|    let tls_config = if features.tls_config {
166|        Some(client.tls_config().await.map_err(|e| {
167|            format!("error getting TLS config: {e}")
168|        })?)
169|    } else {
170|        None
171|    };
172|
173|    Ok(OriginData {
174|        status,
175|        profile_info,
176|        parental,
177|        safe_search,
178|        safe_browsing,
179|        rewrite_settings,
180|        rewrite_entries,
181|        blocked_services_schedule,
182|        filters,
183|        clients,
184|        query_log_config,
185|        stats_config,
186|        access_list,
187|        dns_config,
188|        dhcp_server_config,
189|        tls_config,
190|    })
191|}
192|
193|/// Sync origin data to a single replica.
194|async fn sync_to_replica(
195|    cfg: &Config,
196|    replica: &AdGuardInstance,
197|    origin: &OriginData,
198|    timeout: Option<std::time::Duration>,
199|) -> Result<(), String> {
200|    let replica_client =
201|        Client::new(replica, timeout).map_err(|e| e.to_string())?;
202|
203|    info!(to = replica_client.host(), "Start sync");
204|    let start = Instant::now();
205|
206|    // Get replica status (with auto-setup)
207|    let replica_status = match replica_client.status().await {
208|        Ok(s) => s,
209|        Err(ClientError::SetupNeeded) if replica.auto_setup => {
210|            replica_client.setup().await.map_err(|e| {
211|                format!("error setting up replica: {e}")
212|            })?;
213|            replica_client.status().await.map_err(|e| {
214|                format!("error getting replica status after setup: {e}")
215|            })?
216|        }
217|        Err(e) => return Err(format!("error getting replica status: {e}")),
218|    };
219|
220|    info!(version = %replica_status.version, "Connected to replica");
221|
222|    let ctx = ActionContext {
223|        features: &cfg.features,
224|        continue_on_error: cfg.continue_on_error,
225|        replica,
226|    };
227|
228|    // Run each sync action
229|    let actions: Vec<(&str, Box<dyn Fn(&Client, &OriginData, &ActionContext) -> Result<(), String> + Send + Sync>)> =
230|        actions::build_actions(cfg);
231|
232|    let mut with_error = false;
233|
234|    for (name, action) in &actions {
235|        if let Err(e) = action(&replica_client, origin, &ctx) {
236|            error!(action = name, error = %e, "Error syncing");
237|            with_error = true;
238|            if !cfg.continue_on_error {
239|                let elapsed = start.elapsed().as_secs_f64();
240|                info!(duration = %format!("{elapsed}s"), "Sync done with errors");
241|                return Err(e);
242|            }
243|        }
244|    }
245|
246|    let elapsed = start.elapsed().as_secs_f64();
247|    if with_error {
248|        error!(duration = %format!("{elapsed}s"), "Sync done");
249|    } else {
250|        info!(duration = %format!("{elapsed}s"), "Sync done");
251|    }
252|
253|    // TODO: update metrics (sync_duration, sync_successful)
254|
255|    Ok(())
256|}
257|
258|fn parse_timeout(s: Option<&str>) -> Option<std::time::Duration> {
259|    let s = s?;
260|    humantime::parse_duration(s).ok()
261|}
262|
263|/// Generate a list of last 24 hours formatted labels.
264|pub fn last_24_hours() -> Vec<String> {
265|    use chrono::{Duration, Utc};
266|    let now = Utc::now();
267|    (0..24)
268|        .rev()
269|        .map(|i| {
270|            let t = now - Duration::hours(i);
271|            t.format("%d %b %H:%M").to_string()
272|        })
273|        .collect()
274|}
275|