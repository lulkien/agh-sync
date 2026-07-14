1|1|//! Per-feature sync actions.
2|2|//!
3|3|//! Each action fetches the replica's current state, compares with origin, and pushes the diff.
4|4|
5|5|6|
6|7|use crate::client::Client;
7|8|use crate::config::Config;
8|9|use crate::model::{
9|10|    AccessList, BlockedServicesSchedule, ClientSettings, Clients, DnsConfig, DhcpStaticLease,
10|11|    DhcpStatus, Filter, FilterStatus, ProfileInfo, QueryLogConfig, RewriteEntry, RewriteSettings,
11|12|    SafeSearchConfig, ServerStatus, StatsConfig, TlsConfig,
12|13|};
13|14|
14|15|use super::orchestrator::{ActionContext, OriginData};
15|16|
16|17|type SyncAction =
17|18|    Box<dyn Fn(&Client, &OriginData, &ActionContext) -> Result<(), String> + Send + Sync>;
18|19|
19|20|/// Build the ordered list of sync actions based on feature flags.
20|21|pub(crate) fn build_actions(cfg: &Config) -> Vec<(&'static str, SyncAction)> {
21|22|    let mut actions: Vec<(&str, SyncAction)> = Vec::new();
22|23|
23|24|    if cfg.features.general_settings {
24|25|        actions.push(("profile info", Box::new(sync_profile_info)));
25|26|        if cfg.features.protection_status {
26|27|            actions.push(("protection", Box::new(sync_protection)));
27|28|        }
28|29|        actions.push(("parental", Box::new(sync_parental)));
29|30|        actions.push(("safe search config", Box::new(sync_safe_search)));
30|31|        actions.push(("safe browsing", Box::new(sync_safe_browsing)));
31|32|    }
32|33|
33|34|    if cfg.features.dns.server_config {
34|35|        actions.push(("DNS server config", Box::new(sync_dns_server_config)));
35|36|    }
36|37|
37|38|    if cfg.features.query_log_config {
38|39|        actions.push(("query log config", Box::new(sync_query_log_config)));
39|40|    }
40|41|
41|42|    if cfg.features.stats_config {
42|43|        actions.push(("stats config", Box::new(sync_stats_config)));
43|44|    }
44|45|
45|46|    if cfg.features.dns.rewrites {
46|47|        actions.push(("DNS rewrite settings", Box::new(sync_rewrite_settings)));
47|48|        actions.push(("DNS rewrite entries", Box::new(sync_rewrite_entries)));
48|49|    }
49|50|
50|51|    if cfg.features.filters.blacklist
51|52|        || cfg.features.filters.whitelist
52|53|        || cfg.features.filters.user_rules
53|54|    {
54|55|        actions.push(("filters", Box::new(sync_filters)));
55|56|    }
56|57|
57|58|    if cfg.features.services {
58|59|        actions.push((
59|60|            "blocked services schedule",
60|61|            Box::new(sync_blocked_services),
61|62|        ));
62|63|    }
63|64|
64|65|    if cfg.features.client_settings {
65|66|        actions.push(("client settings", Box::new(sync_client_settings)));
66|67|    }
67|68|
68|69|    if cfg.features.dns.access_lists {
69|70|        actions.push(("DNS access lists", Box::new(sync_dns_access_lists)));
70|71|    }
71|72|
72|73|    if cfg.features.dhcp.server_config {
73|74|        actions.push(("DHCP server config", Box::new(sync_dhcp_server_config)));
74|75|    }
75|76|
76|77|    if cfg.features.dhcp.static_leases {
77|78|        actions.push(("DHCP static leases", Box::new(sync_dhcp_static_leases)));
78|79|    }
79|80|
80|81|    if cfg.features.tls_config {
81|82|        actions.push(("TLS config", Box::new(sync_tls_config)));
82|83|    }
83|84|
84|85|    actions
85|86|}
86|87|
87|88|// ── Profile info (theme sync) ──
88|89|
89|90|fn sync_profile_info(
90|91|    client: &Client,
91|92|    origin: &OriginData,
92|93|    _ctx: &ActionContext,
93|94|) -> Result<(), String> {
94|95|    let replica_profile = client.profile_info().await.ok();
95|96|    let origin_profile = match &origin.profile_info {
96|97|        Some(p) => p,
97|98|        None => return Ok(()),
98|99|    };
99|100|
100|101|    if replica_profile.as_ref().map(|p| p.theme.as_deref()) != Some(origin_profile.theme.as_deref()) {
101|102|        client
102|103|            .set_profile_info(origin_profile)
103|104|            .map_err(|e| format!("profile info: {e}"))?;
104|105|    }
105|106|    Ok(())
106|107|}
107|108|
108|109|// ── Protection ──
109|110|
110|111|fn sync_protection(
111|112|    client: &Client,
112|113|    origin: &OriginData,
113|114|    _ctx: &ActionContext,
114|115|) -> Result<(), String> {
115|116|    let replica_status = client
116|117|        .status()
117|118|        .map_err(|e| format!("protection status: {e}"))?;
118|119|
119|120|    if origin.status.protection_enabled != replica_status.protection_enabled {
120|121|        client
121|122|            .toggle_protection(origin.status.protection_enabled)
122|123|            .map_err(|e| format!("toggle protection: {e}"))?;
123|124|    }
124|125|    Ok(())
125|126|}
126|127|
127|128|// ── Parental ──
128|129|
129|130|fn sync_parental(
130|131|    client: &Client,
131|132|    origin: &OriginData,
132|133|    _ctx: &ActionContext,
133|134|) -> Result<(), String> {
134|135|    let replica_parental = client
135|136|        .parental()
136|137|        .map_err(|e| format!("parental: {e}"))?;
137|138|    if origin.parental != replica_parental {
138|139|        client
139|140|            .toggle_parental(origin.parental)
140|141|            .map_err(|e| format!("toggle parental: {e}"))?;
141|142|    }
142|143|    Ok(())
143|144|}
144|145|
145|146|// ── Safe search ──
146|147|
147|148|fn sync_safe_search(
148|149|    client: &Client,
149|150|    origin: &OriginData,
150|151|    _ctx: &ActionContext,
151|152|) -> Result<(), String> {
152|153|    let replica_ss = client
153|154|        .safe_search_config()
154|155|        .map_err(|e| format!("safe search: {e}"))?;
155|156|    if !safe_search_eq(&origin.safe_search, &replica_ss) {
156|157|        client
157|158|            .set_safe_search_config(&origin.safe_search)
158|159|            .map_err(|e| format!("set safe search: {e}"))?;
159|160|    }
160|161|    Ok(())
161|162|}
162|163|
163|164|fn safe_search_eq(a: &SafeSearchConfig, b: &SafeSearchConfig) -> bool {
164|165|    a.enabled == b.enabled
165|166|        && a.bing == b.bing
166|167|        && a.google == b.google
167|168|        && a.youtube == b.youtube
168|169|        && a.pixabay == b.pixabay
169|170|        && a.duckduckgo == b.duckduckgo
170|171|        && a.yandex == b.yandex
171|172|}
172|173|
173|174|// ── Safe browsing ──
174|175|
175|176|fn sync_safe_browsing(
176|177|    client: &Client,
177|178|    origin: &OriginData,
178|179|    _ctx: &ActionContext,
179|180|) -> Result<(), String> {
180|181|    let replica_sb = client
181|182|        .safe_browsing()
182|183|        .map_err(|e| format!("safe browsing: {e}"))?;
183|184|    if origin.safe_browsing != replica_sb {
184|185|        client
185|186|            .toggle_safe_browsing(origin.safe_browsing)
186|187|            .map_err(|e| format!("toggle safe browsing: {e}"))?;
187|188|    }
188|189|    Ok(())
189|190|}
190|191|
191|192|// ── DNS server config ──
192|193|
193|194|fn sync_dns_server_config(
194|195|    client: &Client,
195|196|    origin: &OriginData,
196|197|    _ctx: &ActionContext,
197|198|) -> Result<(), String> {
198|199|    let replica_dns = client
199|200|        .dns_config()
200|201|        .map_err(|e| format!("DNS config: {e}"))?;
201|202|    // Simple comparison: compare upstream_dns and key fields
202|203|    if !dns_config_eq(&origin.dns_config, &replica_dns) {
203|204|        let mut desired = origin.dns_config.clone();
204|205|        desired.protection_enabled = None; // Don't touch protection via DNS config
205|206|        client
206|207|            .set_dns_config(&desired)
207|208|            .map_err(|e| format!("set DNS config: {e}"))?;
208|209|    }
209|210|    Ok(())
210|211|}
211|212|
212|213|fn dns_config_eq(a: &DnsConfig, b: &DnsConfig) -> bool {
213|214|    a.upstream_dns == b.upstream_dns
214|215|        && a.bootstrap_dns == b.bootstrap_dns
215|216|        && a.ratelimit == b.ratelimit
216|217|        && a.blocking_mode == b.blocking_mode
217|218|        && a.blocking_ipv4 == b.blocking_ipv4
218|219|        && a.blocking_ipv6 == b.blocking_ipv6
219|220|        && a.edns_cs_enabled == b.edns_cs_enabled
220|221|        && a.dnssec_enabled == b.dnssec_enabled
221|222|        && a.disable_ipv6 == b.disable_ipv6
222|223|        && a.cache_size == b.cache_size
223|224|        && a.cache_ttl_min == b.cache_ttl_min
224|225|        && a.cache_ttl_max == b.cache_ttl_max
225|226|}
226|227|
227|228|// ── Query log config ──
228|229|
229|230|fn sync_query_log_config(
230|231|    client: &Client,
231|232|    origin: &OriginData,
232|233|    _ctx: &ActionContext,
233|234|) -> Result<(), String> {
234|235|    let replica_qlc = client
235|236|        .query_log_config()
236|237|        .map_err(|e| format!("query log config: {e}"))?;
237|238|    if !query_log_config_eq(&origin.query_log_config, &replica_qlc) {
238|239|        client
239|240|            .set_query_log_config(&origin.query_log_config)
240|241|            .map_err(|e| format!("set query log config: {e}"))?;
241|242|    }
242|243|    Ok(())
243|244|}
244|245|
245|246|fn query_log_config_eq(a: &QueryLogConfig, b: &QueryLogConfig) -> bool {
246|247|    a.enabled == b.enabled
247|248|        && a.interval == b.interval
248|249|        && a.anonymize_client_ip == b.anonymize_client_ip
249|250|        && a.ignored == b.ignored
250|251|}
251|252|
252|253|// ── Stats config ──
253|254|
254|255|fn sync_stats_config(
255|256|    client: &Client,
256|257|    origin: &OriginData,
257|258|    _ctx: &ActionContext,
258|259|) -> Result<(), String> {
259|260|    let replica_sc = client
260|261|        .stats_config()
261|262|        .map_err(|e| format!("stats config: {e}"))?;
262|263|    if origin.stats_config.interval != replica_sc.interval {
263|264|        client
264|265|            .set_stats_config(&origin.stats_config)
265|266|            .map_err(|e| format!("set stats config: {e}"))?;
266|267|    }
267|268|    Ok(())
268|269|}
269|270|
270|271|// ── Rewrite settings ──
271|272|
272|273|fn sync_rewrite_settings(
273|274|    client: &Client,
274|275|    origin: &OriginData,
275|276|    _ctx: &ActionContext,
276|277|) -> Result<(), String> {
277|278|    let replica_rs = client
278|279|        .rewrite_settings()
279|280|        .map_err(|e| format!("rewrite settings: {e}"))?;
280|281|    if origin.rewrite_settings.enabled != replica_rs.enabled {
281|282|        client
282|283|            .set_rewrite_settings(&origin.rewrite_settings)
283|284|            .map_err(|e| format!("set rewrite settings: {e}"))?;
284|285|    }
285|286|    Ok(())
286|287|}
287|288|
288|289|// ── Rewrite entries ──
289|290|
290|291|fn sync_rewrite_entries(
291|292|    client: &Client,
292|293|    origin: &OriginData,
293|294|    _ctx: &ActionContext,
294|295|) -> Result<(), String> {
295|296|    let replica_entries = client
296|297|        .rewrite_entries()
297|298|        .map_err(|e| format!("rewrite entries: {e}"))?;
298|299|
299|300|    let (adds, removes, _updates, _dupes) =
300|301|        merge_rewrite_entries(&replica_entries, &origin.rewrite_entries);
301|302|
302|303|    client
303|304|        .delete_rewrite_entries(&removes)
304|305|        .map_err(|e| format!("delete rewrite entries: {e}"))?;
305|306|    client
306|307|        .add_rewrite_entries(&adds)
307|308|        .map_err(|e| format!("add rewrite entries: {e}"))?;
308|309|
309|310|    Ok(())
310|311|}
311|312|
312|313|fn merge_rewrite_entries(
313|314|    current: &[RewriteEntry],
314|315|    desired: &[RewriteEntry],
315|316|) -> (
316|317|    Vec<RewriteEntry>,
317|318|    Vec<RewriteEntry>,
318|319|    Vec<RewriteEntry>,
319|320|    Vec<RewriteEntry>,
320|321|) {
321|322|    let mut adds = Vec::new();
322|323|    let mut removes = Vec::new();
323|324|    let _updates = Vec::new();
324|325|    let _dupes = Vec::new();
325|326|
326|327|    let current_set: std::collections::HashSet<_> =
327|328|        current.iter().map(|e| (&e.domain, &e.answer)).collect();
328|329|    let desired_set: std::collections::HashSet<_> =
329|330|        desired.iter().map(|e| (&e.domain, &e.answer)).collect();
330|331|
331|332|    // Remove entries in current but not in desired
332|333|    for e in current {
333|334|        if !desired_set.contains(&(&e.domain, &e.answer)) {
334|335|            removes.push(e.clone());
335|336|        }
336|337|    }
337|338|
338|339|    // Add entries in desired but not in current
339|340|    for e in desired {
340|341|        if !current_set.contains(&(&e.domain, &e.answer)) {
341|342|            adds.push(e.clone());
342|343|        }
343|344|    }
344|345|
345|346|    (adds, removes, updates, dupes)
346|347|}
347|348|
348|349|// ── Filters ──
349|350|
350|351|fn sync_filters(
351|352|    client: &Client,
352|353|    origin: &OriginData,
353|354|    ctx: &ActionContext,
354|355|) -> Result<(), String> {
355|356|    let replica_filters = client
356|357|        .filtering()
357|358|        .map_err(|e| format!("filters: {e}"))?;
358|359|
359|360|    let origin_blacklist = origin.filters.filters.as_ref();
360|361|    let replica_blacklist = replica_filters.filters.as_ref();
361|362|
362|363|    let origin_whitelist = origin.filters.whitelist_filters.as_ref();
363|364|    let replica_whitelist = replica_filters.whitelist_filters.as_ref();
364|365|
365|366|    // Sync blacklist
366|367|    if ctx.features.filters.blacklist {
367|368|        sync_filter_list(client, false, origin_blacklist, replica_blacklist)?;
368|369|    }
369|370|
370|371|    // Sync whitelist
371|372|    if ctx.features.filters.whitelist {
372|373|        sync_filter_list(client, true, origin_whitelist, replica_whitelist)?;
373|374|    }
374|375|
375|376|    // Sync user rules
376|377|    if ctx.features.filters.user_rules {
377|378|        let origin_rules = origin.filters.user_rules.as_deref().unwrap_or(&[]);
378|379|        let replica_rules = replica_filters.user_rules.as_deref().unwrap_or(&[]);
379|380|
380|381|        if origin_rules != replica_rules {
381|382|            client
382|383|                .set_custom_rules(origin_rules)
383|384|                .map_err(|e| format!("set custom rules: {e}"))?;
384|385|        }
385|386|    }
386|387|
387|388|    // Sync filtering enabled/interval
388|389|    if let (Some(ref enabled), Some(ref interval)) =
389|390|        (origin.filters.enabled, origin.filters.interval)
390|391|    {
391|392|        if replica_filters.enabled.as_ref() != Some(enabled)
392|393|            || replica_filters.interval.as_ref() != Some(interval)
393|394|        {
394|395|            client
395|396|                .toggle_filtering(*enabled, *interval)
396|397|                .map_err(|e| format!("toggle filtering: {e}"))?;
397|398|        }
398|399|    }
399|400|
400|401|    Ok(())
401|402|}
402|403|
403|404|fn sync_filter_list(
404|405|    client: &Client,
405|406|    whitelist: bool,
406|407|    origin_filters: Option<&Vec<Filter>>,
407|408|    replica_filters: Option<&Vec<Filter>>,
408|409|) -> Result<(), String> {
409|410|    let origin = origin_filters.map(|f| f.as_slice()).unwrap_or(&[]);
410|411|    let replica = replica_filters.map(|f| f.as_slice()).unwrap_or(&[]);
411|412|
412|413|    let origin_urls: std::collections::HashSet<_> = origin.iter().map(|f| &f.url).collect();
413|414|    let replica_urls: std::collections::HashSet<_> = replica.iter().map(|f| &f.url).collect();
414|415|
415|416|    // Remove filters not in origin
416|417|    for f in replica {
417|418|        if !origin_urls.contains(&f.url) {
418|419|            client
419|420|                .delete_filter(whitelist, f)
420|421|                .map_err(|e| format!("delete filter: {e}"))?;
421|422|        }
422|423|    }
423|424|
424|425|    // Add new filters from origin
425|426|    for f in origin {
426|427|        if !replica_urls.contains(&f.url) {
427|428|            client
428|429|                .add_filter(whitelist, f)
429|430|                .map_err(|e| format!("add filter: {e}"))?;
430|431|        }
431|432|    }
432|433|
433|434|    // Refresh if anything changed
434|435|    if origin_urls != replica_urls {
435|436|        client
436|437|            .refresh_filters(whitelist)
437|438|            .map_err(|e| format!("refresh filters: {e}"))?;
438|439|    }
439|440|
440|441|    Ok(())
441|442|}
442|443|
443|444|// ── Blocked services ──
444|445|
445|446|fn sync_blocked_services(
446|447|    client: &Client,
447|448|    origin: &OriginData,
448|449|    _ctx: &ActionContext,
449|450|) -> Result<(), String> {
450|451|    let replica_bss = client
451|452|        .blocked_services_schedule()
452|453|        .map_err(|e| format!("blocked services: {e}"))?;
453|454|
454|455|    if !blocked_services_eq(&origin.blocked_services_schedule, &replica_bss) {
455|456|        client
456|457|            .set_blocked_services_schedule(&origin.blocked_services_schedule)
457|458|            .map_err(|e| format!("set blocked services: {e}"))?;
458|459|    }
459|460|    Ok(())
460|461|}
461|462|
462|463|fn blocked_services_eq(a: &BlockedServicesSchedule, b: &BlockedServicesSchedule) -> bool {
463|464|    a.services == b.services
464|465|        && a.schedule.time_zone == b.schedule.time_zone
465|466|        && a.schedule.days == b.schedule.days
466|467|        && a.schedule.start == b.schedule.start
467|468|        && a.schedule.end == b.schedule.end
468|469|}
469|470|
470|471|// ── Client settings ──
471|472|
472|473|fn sync_client_settings(
473|474|    client: &Client,
474|475|    origin: &OriginData,
475|476|    _ctx: &ActionContext,
476|477|) -> Result<(), String> {
477|478|    let replica_clients = client
478|479|        .clients()
479|480|        .map_err(|e| format!("clients: {e}"))?;
480|481|
481|482|    let origin_names: std::collections::HashSet<_> =
482|483|        origin.clients.clients.iter().map(|c| &c.name).collect();
483|484|    let replica_names: std::collections::HashSet<_> =
484|485|        replica_clients.clients.iter().map(|c| &c.name).collect();
485|486|
486|487|    // Delete clients not in origin
487|488|    for c in &replica_clients.clients {
488|489|        if !origin_names.contains(&c.name) {
489|490|            client
490|491|                .delete_client(c)
491|492|                .map_err(|e| format!("delete client: {e}"))?;
492|493|        }
493|494|    }
494|495|
495|496|    // Add or update clients from origin
496|497|    for c in &origin.clients.clients {
497|498|        if !replica_names.contains(&c.name) {
498|499|            client
499|500|                .add_client(c)
500|501|