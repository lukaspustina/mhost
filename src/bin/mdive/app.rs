use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mhost::app::common::ordinal::Ordinal;
use mhost::app::common::rdata_format::{format_rdata, format_rdata_human};
use mhost::app::common::resolver_args::ResolverArgs;
use mhost::app::common::subdomain_spec::{default_entries, Category, SubdomainEntry};
use mhost::resolver::lookup::{LookupResult, Lookups};
use mhost::resolver::ResolverGroup;
use mhost::resolver::Error as ResolverError;
use mhost::resources::rdata::RData;
use mhost::services::whois::WhoisResponses;
use mhost::{Name, RecordType};
use ratatui::widgets::TableState;
use regex::RegexBuilder;
use tokio::task::JoinHandle;

use crate::lints::{self, LintSection};

/// All categories available for toggling, in display order.
/// Keys 1-9 map to indices 0-8, key 0 maps to index 9.
pub const TOGGLEABLE_CATEGORIES: &[Category] = &[
    Category::EmailAuthentication,  // 1
    Category::EmailServices,        // 2
    Category::TlsDane,              // 3
    Category::Communication,        // 4
    Category::CalendarContacts,     // 5
    Category::Infrastructure,       // 6
    Category::ModernProtocols,      // 7
    Category::VerificationMetadata, // 8
    Category::Legacy,               // 9
    Category::Gaming,               // 0
];

/// Default active categories on startup (Legacy and Gaming off by default).
const DEFAULT_CATEGORIES: &[Category] = &[
    Category::EmailAuthentication,
    Category::EmailServices,
    Category::TlsDane,
    Category::Communication,
    Category::CalendarContacts,
    Category::Infrastructure,
    Category::ModernProtocols,
    Category::VerificationMetadata,
];

pub fn category_short_label(cat: Category) -> &'static str {
    match cat {
        Category::EmailAuthentication => "Email",
        Category::EmailServices => "Svc",
        Category::TlsDane => "TLS",
        Category::Communication => "Comm",
        Category::CalendarContacts => "Cal",
        Category::Infrastructure => "Infra",
        Category::ModernProtocols => "Modern",
        Category::VerificationMetadata => "Verify",
        Category::Legacy => "Legacy",
        Category::Gaming => "Gaming",
        Category::Apex => "Apex",
        Category::Discovered => "Disc",
    }
}

fn category_ordinal(cat: Category) -> u8 {
    match cat {
        Category::Apex => 0,
        Category::EmailAuthentication => 1,
        Category::EmailServices => 2,
        Category::TlsDane => 3,
        Category::Communication => 4,
        Category::CalendarContacts => 5,
        Category::Infrastructure => 6,
        Category::ModernProtocols => 7,
        Category::VerificationMetadata => 8,
        Category::Legacy => 9,
        Category::Gaming => 10,
        Category::Discovered => 11,
    }
}

#[derive(Clone)]
pub struct StatsData {
    pub rr_type_counts: BTreeMap<RecordType, usize>,
    pub total_unique: usize,
    pub responses: usize,
    pub nxdomains: usize,
    pub timeout_errors: usize,
    pub refuse_errors: usize,
    pub servfail_errors: usize,
    pub total_errors: usize,
    pub responding_servers: usize,
    pub min_time_ms: Option<u128>,
    pub max_time_ms: Option<u128>,
}

fn compute_stats(lookups: &Lookups) -> StatsData {
    // Unique record type counts (deduped by name+type+value)
    let mut seen = HashSet::new();
    let mut rr_type_counts = BTreeMap::new();
    for lookup in lookups.iter() {
        for record in lookup.records() {
            let key = (
                record.name().to_string(),
                record.record_type(),
                format_rdata(record.data()),
            );
            if seen.insert(key) {
                *rr_type_counts.entry(record.record_type()).or_insert(0usize) += 1;
            }
        }
    }
    let total_unique: usize = rr_type_counts.values().sum();

    // Query health counts
    let (mut responses, mut nxdomains, mut timeout_errors, mut refuse_errors, mut servfail_errors, mut total_errors) =
        (0, 0, 0, 0, 0, 0);
    for l in lookups.iter() {
        match l.result() {
            LookupResult::Response { .. } => responses += 1,
            LookupResult::NxDomain { .. } => nxdomains += 1,
            LookupResult::Error(ResolverError::Timeout) => {
                timeout_errors += 1;
                total_errors += 1;
            }
            LookupResult::Error(ResolverError::QueryRefused) => {
                refuse_errors += 1;
                total_errors += 1;
            }
            LookupResult::Error(ResolverError::ServerFailure) => {
                servfail_errors += 1;
                total_errors += 1;
            }
            LookupResult::Error { .. } => total_errors += 1,
        }
    }

    // Responding servers
    let responding_servers = lookups
        .iter()
        .filter(|x| x.result().is_response())
        .map(|x| x.name_server().to_string())
        .collect::<HashSet<_>>()
        .len();

    // Response times
    let times: Vec<u128> = lookups
        .iter()
        .filter_map(|x| x.result().response())
        .map(|x| x.response_time().as_millis())
        .collect();
    let min_time_ms = times.iter().min().copied();
    let max_time_ms = times.iter().max().copied();

    StatsData {
        rr_type_counts,
        total_unique,
        responses,
        nxdomains,
        timeout_errors,
        refuse_errors,
        servfail_errors,
        total_errors,
        responding_servers,
        min_time_ms,
        max_time_ms,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Input,
    Search,
}

#[derive(Debug, Clone)]
pub enum QueryState {
    Idle,
    Loading { domain: String },
    Querying { domain: String },
    Done {
        domain: String,
        record_count: usize,
        total_record_count: usize,
        server_count: usize,
        elapsed: Duration,
    },
    Error {
        domain: String,
        message: String,
    },
}

#[derive(Debug, Clone)]
pub struct RecordRow {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub value: String,
    pub human_value: String,
    pub nameserver: String,
    pub category: Category,
    /// Hostname extracted from value for drill-down navigation (l/→ key).
    pub drill_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryStrategy {
    CtLogs,
    Wordlist,
    SrvProbing,
    TxtMining,
    Permutation,
}

impl DiscoveryStrategy {
    pub fn all() -> &'static [DiscoveryStrategy] {
        &[
            DiscoveryStrategy::CtLogs,
            DiscoveryStrategy::Wordlist,
            DiscoveryStrategy::SrvProbing,
            DiscoveryStrategy::TxtMining,
            DiscoveryStrategy::Permutation,
        ]
    }

    pub fn key(self) -> char {
        match self {
            DiscoveryStrategy::CtLogs => 'c',
            DiscoveryStrategy::Wordlist => 'w',
            DiscoveryStrategy::SrvProbing => 's',
            DiscoveryStrategy::TxtMining => 't',
            DiscoveryStrategy::Permutation => 'p',
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DiscoveryStrategy::CtLogs => "CT Logs",
            DiscoveryStrategy::Wordlist => "Wordlist",
            DiscoveryStrategy::SrvProbing => "SRV Probing",
            DiscoveryStrategy::TxtMining => "TXT Mining",
            DiscoveryStrategy::Permutation => "Permutation",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            DiscoveryStrategy::CtLogs => "Search Certificate Transparency logs (crt.sh) for historically issued certificates, revealing subdomains that may not be publicly linked",
            DiscoveryStrategy::Wordlist => "Brute-force 424 common subdomain names (api, mail, cdn, staging, ...) with wildcard filtering to suppress false positives",
            DiscoveryStrategy::SrvProbing => "Probe 22 well-known SRV service records (IMAP, XMPP, SIP, LDAP, CalDAV, Matrix, STUN/TURN, ...)",
            DiscoveryStrategy::TxtMining => "Extract referenced domains from SPF includes/redirects and DMARC rua/ruf mailto URIs in existing TXT records",
            DiscoveryStrategy::Permutation => "Generate variations of discovered subdomain labels with common prefixes/suffixes (dev-, staging-, -test, -prod, -v2, ...)",
        }
    }

    pub fn from_key(c: char) -> Option<DiscoveryStrategy> {
        match c {
            'c' => Some(DiscoveryStrategy::CtLogs),
            'w' => Some(DiscoveryStrategy::Wordlist),
            's' => Some(DiscoveryStrategy::SrvProbing),
            't' => Some(DiscoveryStrategy::TxtMining),
            'p' => Some(DiscoveryStrategy::Permutation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StrategyStatus {
    Idle,
    Running { completed: usize, total: usize },
    Done { found: usize, elapsed: Duration },
    Error(String),
}

#[derive(Clone)]
pub struct DiscoveryState {
    pub statuses: HashMap<DiscoveryStrategy, StrategyStatus>,
    pub wildcard_lookups: Option<Lookups>,
    pub wildcard_checked: bool,
    pub wildcard_running: bool,
    pub generation: u64,
}

impl DiscoveryState {
    fn new(generation: u64) -> Self {
        let mut statuses = HashMap::new();
        for s in DiscoveryStrategy::all() {
            statuses.insert(*s, StrategyStatus::Idle);
        }
        DiscoveryState {
            statuses,
            wildcard_lookups: None,
            wildcard_checked: false,
            wildcard_running: false,
            generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Popup {
    None,
    RecordDetail {
        name: String,
        record_type: RecordType,
        value: String,
    },
    Help,
    Servers,
    Whois,
    Lints,
    Discovery,
}

pub struct HistoryEntry {
    pub domain: String,
    pub input: String,
    pub query_state: QueryState,
    pub lookups: Option<Lookups>,
    pub rows: Vec<RecordRow>,
    pub selected_index: Option<usize>,
    pub stats_data: Option<StatsData>,
    pub whois_data: Option<WhoisResponses>,
    pub whois_error: Option<String>,
    pub lint_results: Option<Vec<LintSection>>,
    pub discovery_state: Option<DiscoveryState>,
    pub category_map: HashMap<(String, RecordType), Category>,
    pub active_categories: HashSet<Category>,
    pub filter: Option<regex::Regex>,
    pub filter_input: String,
    pub batch_progress: (usize, usize),
}

pub enum Action {
    Quit,
    EnterInputMode,
    ExitInputMode,
    EnterSearchMode,
    ExitSearchMode,
    ApplyFilter,
    ClearFilter,
    SubmitQuery,
    InputChar(char),
    InputBackspace,
    InputLeft,
    InputRight,
    InputHome,
    InputEnd,
    InputDeleteWord,
    SelectAll,
    SelectNone,
    ToggleHumanView,
    ToggleStats,
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    Home,
    End,
    OpenRecordDetail,
    DrillIntoName,
    DrillIntoValue,
    GoBack,
    OpenHelp,
    OpenServers,
    OpenWhois,
    OpenLints,
    ClosePopup,
    PopupScrollUp,
    PopupScrollDown,
    PopupScrollPageUp,
    PopupScrollPageDown,
    PopupScrollHome,
    PopupScrollEnd,
    WhoisResult { generation: u64, data: WhoisResponses },
    WhoisError { generation: u64, message: String },
    DigitPress(char),
    PressG,
    PressCapG,
    DnsBatch { generation: u64, lookups: Lookups, completed: usize, total: usize },
    DnsComplete { generation: u64, elapsed: Duration },
    DnsError { generation: u64, message: String },
    OpenDiscovery,
    RunStrategy(DiscoveryStrategy),
    RunAllStrategies,
    DiscoveryBatch { generation: u64, strategy: DiscoveryStrategy, lookups: Lookups, completed: usize, total: usize },
    DiscoveryComplete { generation: u64, strategy: DiscoveryStrategy, found: usize, elapsed: Duration },
    DiscoveryError { generation: u64, strategy: DiscoveryStrategy, message: String },
    WildcardComplete { generation: u64, wildcard_lookups: Option<Lookups> },
}

pub struct App {
    pub resolver_args: ResolverArgs,
    pub mode: Mode,
    pub input: String,
    pub cursor_pos: usize,
    pub filter_input: String,
    pub filter_cursor_pos: usize,
    pub filter: Option<regex::Regex>,
    pub filter_error: Option<String>,
    pub active_categories: HashSet<Category>,
    pub query_state: QueryState,
    pub rows: Vec<RecordRow>,
    pub table_state: TableState,
    pub should_quit: bool,
    pub popup: Popup,
    pub human_view: bool,
    pub batch_progress: (usize, usize),
    pub count_buffer: String,
    pub pending_g: Option<Instant>,
    pub quit_confirm: bool,
    pub(crate) lookups: Option<Lookups>,
    /// Monotonically increasing query generation; used to discard stale DNS results.
    pub(crate) query_generation: u64,
    pub whois_data: Option<WhoisResponses>,
    pub whois_error: Option<String>,
    pub whois_scroll: u16,
    /// True while a WHOIS fetch is in progress.
    pub(crate) whois_loading: bool,
    /// Tracks which query generation a pending/completed WHOIS fetch belongs to,
    /// so stale results from a previous query can be discarded.
    pub(crate) whois_generation: u64,
    pub lint_results: Option<Vec<LintSection>>,
    pub lint_scroll: u16,
    pub show_stats: bool,
    pub stats_data: Option<StatsData>,
    pub discovery_state: Option<DiscoveryState>,
    pub discovery_scroll: u16,
    pub record_detail_scroll: u16,
    pub servers_scroll: u16,
    pub(crate) pending_strategy_spawns: Vec<DiscoveryStrategy>,
    /// Shared resolver group, built once per query.
    pub(crate) resolver_group: Option<Arc<ResolverGroup>>,
    /// Handle for the active DNS query task (aborted on new query).
    pub(crate) dns_task: Option<JoinHandle<()>>,
    /// Handles for active discovery tasks (aborted on new query).
    pub(crate) discovery_tasks: Vec<JoinHandle<()>>,
    /// Cached category lookup map, rebuilt per query domain.
    category_map: HashMap<(String, RecordType), Category>,
    /// Cached default entries (allocated once).
    default_entries: Vec<SubdomainEntry>,
    /// Navigation history stack for drill-down (max 50 entries).
    pub history: Vec<HistoryEntry>,
}

impl App {
    pub fn new(resolver_args: ResolverArgs) -> Self {
        Self {
            resolver_args,
            mode: Mode::Normal,
            input: String::new(),
            cursor_pos: 0,
            filter_input: String::new(),
            filter_cursor_pos: 0,
            filter: None,
            filter_error: None,
            active_categories: DEFAULT_CATEGORIES.iter().copied().collect(),
            query_state: QueryState::Idle,
            rows: Vec::new(),
            table_state: TableState::default(),
            should_quit: false,
            popup: Popup::None,
            human_view: false,
            batch_progress: (0, 0),
            count_buffer: String::new(),
            pending_g: None,
            quit_confirm: false,
            lookups: None,
            query_generation: 0,
            whois_data: None,
            whois_error: None,
            whois_scroll: 0,
            whois_loading: false,
            whois_generation: 0,
            lint_results: None,
            lint_scroll: 0,
            show_stats: false,
            stats_data: None,
            discovery_state: None,
            discovery_scroll: 0,
            record_detail_scroll: 0,
            servers_scroll: 0,
            pending_strategy_spawns: Vec::new(),
            resolver_group: None,
            dns_task: None,
            discovery_tasks: Vec::new(),
            category_map: HashMap::new(),
            default_entries: default_entries(),
            history: Vec::new(),
        }
    }

    /// Returns a mutable reference to the active input buffer and cursor position
    /// for the current mode (Input or Search).
    fn active_input_mut(&mut self) -> (&mut String, &mut usize) {
        match self.mode {
            Mode::Search => (&mut self.filter_input, &mut self.filter_cursor_pos),
            _ => (&mut self.input, &mut self.cursor_pos),
        }
    }

    pub fn update(&mut self, action: Action) {
        // Clear pending_g after 1 second timeout
        if let Some(t) = self.pending_g {
            if t.elapsed() > Duration::from_secs(1) {
                self.pending_g = None;
                self.count_buffer.clear();
            }
        }

        // Reset quit confirmation on any non-Quit action
        if !matches!(action, Action::Quit) {
            self.quit_confirm = false;
        }

        // Vi-count bookkeeping: on non-count actions, flush a single-digit buffer
        // as a category toggle, then clear state.
        match &action {
            Action::DigitPress(_) | Action::PressG | Action::PressCapG => {}
            _ => {
                if self.count_buffer.len() == 1 && self.pending_g.is_none() {
                    let c = self.count_buffer.chars().next().unwrap();
                    let idx = if c == '0' { 9 } else { (c as usize) - ('1' as usize) };
                    if let Some(cat) = TOGGLEABLE_CATEGORIES.get(idx) {
                        if self.active_categories.contains(cat) {
                            self.active_categories.remove(cat);
                        } else {
                            self.active_categories.insert(*cat);
                        }
                        self.rebuild_rows();
                    }
                }
                self.count_buffer.clear();
                self.pending_g = None;
            }
        }

        match action {
            Action::Quit => {
                let has_results = self.lookups.is_some();
                if has_results && !self.quit_confirm {
                    self.quit_confirm = true;
                } else {
                    self.should_quit = true;
                }
            }

            Action::EnterInputMode => {
                self.mode = Mode::Input;
            }
            Action::ExitInputMode => {
                self.mode = Mode::Normal;
            }
            Action::EnterSearchMode => {
                self.filter_input = self.filter.as_ref().map_or(String::new(), |r| r.as_str().to_string());
                self.filter_cursor_pos = self.filter_input.len();
                self.filter_error = None;
                self.mode = Mode::Search;
            }
            Action::ExitSearchMode => {
                self.filter_error = None;
                self.mode = Mode::Normal;
            }
            Action::ApplyFilter => {
                let trimmed = self.filter_input.trim().to_string();
                if trimmed.is_empty() {
                    self.filter = None;
                    self.filter_error = None;
                } else {
                    match RegexBuilder::new(&trimmed)
                        .case_insensitive(true)
                        .size_limit(10 * (1 << 20))
                        .dfa_size_limit(10 * (1 << 20))
                        .build()
                    {
                        Ok(re) => {
                            self.filter = Some(re);
                            self.filter_error = None;
                        }
                        Err(e) => {
                            self.filter_error = Some(e.to_string());
                            return;
                        }
                    }
                }
                self.mode = Mode::Normal;
                self.rebuild_rows();
            }
            Action::ClearFilter => {
                self.filter = None;
                self.filter_error = None;
                self.filter_input.clear();
                self.filter_cursor_pos = 0;
                self.rebuild_rows();
            }
            Action::SubmitQuery => {
                let domain = self.input.trim().to_string();
                if !domain.is_empty() {
                    // Abort existing tasks before starting new query
                    if let Some(handle) = self.dns_task.take() {
                        handle.abort();
                    }
                    for handle in self.discovery_tasks.drain(..) {
                        handle.abort();
                    }
                    self.resolver_group = None;

                    // Manual query clears navigation history (fresh start)
                    self.history.clear();

                    self.mode = Mode::Normal;
                    self.query_generation += 1;
                    self.query_state = QueryState::Loading {
                        domain: domain.clone(),
                    };
                    self.rows.clear();
                    self.lookups = None;
                    self.batch_progress = (0, 0);
                    self.table_state.select(None);
                    self.filter = None;
                    self.filter_error = None;
                    self.filter_input.clear();
                    self.filter_cursor_pos = 0;
                    self.whois_data = None;
                    self.whois_error = None;
                    self.whois_loading = false;
                    self.lint_results = None;
                    self.stats_data = None;
                    self.discovery_state = None;
                    self.category_map.clear();
                }
            }

            Action::InputChar(c) => {
                let (buf, pos) = self.active_input_mut();
                buf.insert(*pos, c);
                *pos += c.len_utf8();
            }
            Action::InputBackspace => {
                let (buf, pos) = self.active_input_mut();
                if *pos > 0 {
                    let prev = buf[..*pos]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    buf.drain(prev..*pos);
                    *pos = prev;
                }
            }
            Action::InputLeft => {
                let (buf, pos) = self.active_input_mut();
                if *pos > 0 {
                    *pos = buf[..*pos]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            Action::InputRight => {
                let (buf, pos) = self.active_input_mut();
                if *pos < buf.len() {
                    *pos = buf[*pos..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| *pos + i)
                        .unwrap_or(buf.len());
                }
            }
            Action::InputHome => {
                let (_buf, pos) = self.active_input_mut();
                *pos = 0;
            }
            Action::InputEnd => {
                let (buf, pos) = self.active_input_mut();
                *pos = buf.len();
            }
            Action::InputDeleteWord => {
                let (buf, pos) = self.active_input_mut();
                if *pos > 0 {
                    let new_pos = buf[..*pos]
                        .trim_end()
                        .rfind(|c: char| c.is_whitespace())
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    buf.drain(new_pos..*pos);
                    *pos = new_pos;
                }
            }

            Action::SelectAll => {
                for cat in TOGGLEABLE_CATEGORIES {
                    self.active_categories.insert(*cat);
                }
                self.rebuild_rows();
            }
            Action::SelectNone => {
                self.active_categories.clear();
                self.rebuild_rows();
            }
            Action::ToggleHumanView => {
                self.human_view = !self.human_view;
            }
            Action::ToggleStats => {
                self.show_stats = !self.show_stats;
            }

            Action::MoveUp => {
                let i = match self.table_state.selected() {
                    Some(i) => i.saturating_sub(1),
                    None if !self.rows.is_empty() => 0,
                    None => return,
                };
                self.table_state.select(Some(i));
            }
            Action::MoveDown => {
                if self.rows.is_empty() {
                    return;
                }
                let i = match self.table_state.selected() {
                    Some(i) => (i + 1).min(self.rows.len() - 1),
                    None => 0,
                };
                self.table_state.select(Some(i));
            }
            Action::PageUp => {
                let i = match self.table_state.selected() {
                    Some(i) => i.saturating_sub(10),
                    None if !self.rows.is_empty() => 0,
                    None => return,
                };
                self.table_state.select(Some(i));
            }
            Action::PageDown => {
                if self.rows.is_empty() {
                    return;
                }
                let i = match self.table_state.selected() {
                    Some(i) => (i + 10).min(self.rows.len() - 1),
                    None => 0,
                };
                self.table_state.select(Some(i));
            }
            Action::Home => {
                if !self.rows.is_empty() {
                    self.table_state.select(Some(0));
                }
            }
            Action::End => {
                if !self.rows.is_empty() {
                    self.table_state.select(Some(self.rows.len() - 1));
                }
            }

            Action::DigitPress(c) => {
                if self.count_buffer.len() < 6 {
                    self.count_buffer.push(c);
                }
            }
            Action::PressG => {
                if self.pending_g.is_some() {
                    // Second g: jump to line N or top
                    self.pending_g = None;
                    let line = self.count_buffer.parse::<usize>().unwrap_or(0);
                    self.count_buffer.clear();
                    if !self.rows.is_empty() {
                        if line > 0 {
                            self.table_state
                                .select(Some((line - 1).min(self.rows.len() - 1)));
                        } else {
                            self.table_state.select(Some(0));
                        }
                    }
                } else {
                    self.pending_g = Some(Instant::now());
                }
            }
            Action::PressCapG => {
                self.pending_g = None;
                let line = self.count_buffer.parse::<usize>().unwrap_or(0);
                self.count_buffer.clear();
                if !self.rows.is_empty() {
                    if line > 0 {
                        self.table_state
                            .select(Some((line - 1).min(self.rows.len() - 1)));
                    } else {
                        self.table_state.select(Some(self.rows.len() - 1));
                    }
                }
            }

            Action::OpenRecordDetail => {
                if let Some(idx) = self.table_state.selected() {
                    if let Some(row) = self.rows.get(idx) {
                        self.record_detail_scroll = 0;
                        self.popup = Popup::RecordDetail {
                            name: row.name.clone(),
                            record_type: row.record_type,
                            value: row.value.clone(),
                        };
                    }
                }
            }
            Action::DrillIntoName => {
                // Only drill when a row is selected and query is done
                if !matches!(self.query_state, QueryState::Done { .. }) {
                    return;
                }
                if let Some(idx) = self.table_state.selected() {
                    if let Some(row) = self.rows.get(idx) {
                        let target = row.name.trim_end_matches('.').to_string();
                        let current = self.current_domain().trim_end_matches('.');
                        if !target.is_empty() && target != current {
                            self.drill_to(target);
                        }
                    }
                }
            }
            Action::DrillIntoValue => {
                if !matches!(self.query_state, QueryState::Done { .. }) {
                    return;
                }
                if let Some(idx) = self.table_state.selected() {
                    if let Some(row) = self.rows.get(idx) {
                        if let Some(ref target) = row.drill_target {
                            let target = target.trim_end_matches('.').to_string();
                            let current = self.current_domain().trim_end_matches('.');
                            if !target.is_empty() && target != "." && target != current {
                                self.drill_to(target);
                            }
                        }
                    }
                }
            }
            Action::GoBack => {
                // Abort any running tasks before restoring
                if let Some(handle) = self.dns_task.take() {
                    handle.abort();
                }
                for handle in self.discovery_tasks.drain(..) {
                    handle.abort();
                }
                self.pop_history();
            }
            Action::OpenHelp => {
                self.popup = Popup::Help;
            }
            Action::OpenServers => {
                self.popup = Popup::Servers;
                self.servers_scroll = 0;
            }
            Action::OpenWhois => {
                self.popup = Popup::Whois;
                self.whois_scroll = 0;
            }
            Action::OpenLints => {
                self.popup = Popup::Lints;
                self.lint_scroll = 0;
                if self.lint_results.is_none() {
                    if let Some(ref lookups) = self.lookups {
                        self.lint_results = Some(lints::run_lints(lookups));
                    }
                }
            }
            Action::WhoisResult { generation, data } => {
                if generation == self.query_generation {
                    self.whois_data = Some(data);
                    self.whois_error = None;
                    self.whois_loading = false;
                }
            }
            Action::WhoisError { generation, message } => {
                if generation == self.query_generation {
                    self.whois_error = Some(message);
                    self.whois_loading = false;
                }
            }
            Action::ClosePopup => {
                self.popup = Popup::None;
            }
            Action::PopupScrollUp => {
                self.popup_scroll_mut(|s| *s = s.saturating_sub(1));
            }
            Action::PopupScrollDown => {
                self.popup_scroll_mut(|s| *s = s.saturating_add(1));
            }
            Action::PopupScrollPageUp => {
                self.popup_scroll_mut(|s| *s = s.saturating_sub(10));
            }
            Action::PopupScrollPageDown => {
                self.popup_scroll_mut(|s| *s = s.saturating_add(10));
            }
            Action::PopupScrollHome => {
                self.popup_scroll_mut(|s| *s = 0);
            }
            Action::PopupScrollEnd => {
                self.popup_scroll_mut(|s| *s = u16::MAX);
            }

            Action::OpenDiscovery => {
                if self.lookups.is_some() {
                    self.popup = Popup::Discovery;
                    self.discovery_scroll = 0;
                    if self.discovery_state.is_none() {
                        self.discovery_state = Some(DiscoveryState::new(self.query_generation));
                    }
                }
            }
            Action::RunStrategy(strategy) => {
                if let Some(ref mut state) = self.discovery_state {
                    if matches!(state.statuses.get(&strategy), Some(StrategyStatus::Running { .. })) {
                        return; // already running
                    }
                    state.statuses.insert(strategy, StrategyStatus::Running { completed: 0, total: 0 });
                    self.pending_strategy_spawns.push(strategy);
                }
            }
            Action::RunAllStrategies => {
                if let Some(ref mut state) = self.discovery_state {
                    for &strategy in DiscoveryStrategy::all() {
                        if !matches!(state.statuses.get(&strategy), Some(StrategyStatus::Running { .. })) {
                            state.statuses.insert(strategy, StrategyStatus::Running { completed: 0, total: 0 });
                            self.pending_strategy_spawns.push(strategy);
                        }
                    }
                }
            }
            Action::DiscoveryBatch { generation, strategy, lookups, completed, total } => {
                let state = match self.discovery_state {
                    Some(ref mut s) if s.generation == generation => s,
                    _ => return,
                };
                state.statuses.insert(strategy, StrategyStatus::Running { completed, total });
                match self.lookups.take() {
                    Some(existing) => self.lookups = Some(existing.merge(lookups)),
                    None => self.lookups = Some(lookups),
                }
                self.stats_data = self.lookups.as_ref().map(compute_stats);
                self.rebuild_rows();
                if !self.rows.is_empty() && self.table_state.selected().is_none() {
                    self.table_state.select(Some(0));
                }
            }
            Action::DiscoveryComplete { generation, strategy, found, elapsed } => {
                if let Some(ref mut state) = self.discovery_state {
                    if state.generation == generation {
                        state.statuses.insert(strategy, StrategyStatus::Done { found, elapsed });
                    }
                }
            }
            Action::DiscoveryError { generation, strategy, message } => {
                if let Some(ref mut state) = self.discovery_state {
                    if state.generation == generation {
                        state.statuses.insert(strategy, StrategyStatus::Error(message));
                    }
                }
            }
            Action::WildcardComplete { generation, wildcard_lookups } => {
                if let Some(ref mut state) = self.discovery_state {
                    if state.generation == generation {
                        state.wildcard_lookups = wildcard_lookups;
                        state.wildcard_checked = true;
                        state.wildcard_running = false;
                    }
                }
            }

            Action::DnsBatch { generation, lookups, completed, total } => {
                if generation != self.query_generation {
                    return; // discard stale results from a previous query
                }
                self.batch_progress = (completed, total);
                match self.lookups.take() {
                    Some(existing) => self.lookups = Some(existing.merge(lookups)),
                    None => self.lookups = Some(lookups),
                }
                self.stats_data = self.lookups.as_ref().map(compute_stats);
                self.rebuild_rows();
                if !self.rows.is_empty() && self.table_state.selected().is_none() {
                    self.table_state.select(Some(0));
                }
            }
            Action::DnsComplete { generation, elapsed } => {
                if generation != self.query_generation {
                    return; // discard stale completion from a previous query
                }
                let server_count = self.lookups.as_ref().map_or(0, |lookups| {
                    let mut servers = HashSet::new();
                    for lookup in lookups.iter() {
                        servers.insert(lookup.name_server().to_string());
                    }
                    servers.len()
                });
                // Count total unique records (before category filtering)
                let total_record_count = self.lookups.as_ref().map_or(0, |lookups| {
                    let mut seen = HashSet::new();
                    for lookup in lookups.iter() {
                        for record in lookup.records() {
                            let key = (
                                record.name().to_string(),
                                record.record_type(),
                                format_rdata(record.data()),
                            );
                            seen.insert(key);
                        }
                    }
                    seen.len()
                });
                let domain = self.current_domain().to_string();
                let record_count = self.rows.len();
                self.query_state = QueryState::Done {
                    domain,
                    record_count,
                    total_record_count,
                    server_count,
                    elapsed,
                };
                self.batch_progress = (0, 0);
            }
            Action::DnsError { generation, message } => {
                if generation != self.query_generation {
                    return; // discard stale error from a previous query
                }
                let domain = self.current_domain().to_string();
                self.query_state = QueryState::Error { domain, message };
                self.batch_progress = (0, 0);
            }
        }
    }

    /// Returns true if the WHOIS popup is open and data needs to be fetched.
    pub fn needs_whois_fetch(&self) -> bool {
        self.popup == Popup::Whois
            && self.whois_data.is_none()
            && self.whois_error.is_none()
            && !self.whois_loading
            && self.lookups.is_some()
    }

    /// Returns a mutable reference to the scroll position for the current popup.
    fn popup_scroll_mut(&mut self, f: impl FnOnce(&mut u16)) {
        let scroll = match self.popup {
            Popup::Whois => &mut self.whois_scroll,
            Popup::Lints => &mut self.lint_scroll,
            Popup::Discovery => &mut self.discovery_scroll,
            Popup::RecordDetail { .. } => &mut self.record_detail_scroll,
            Popup::Servers => &mut self.servers_scroll,
            _ => return,
        };
        f(scroll);
    }

    pub fn current_domain(&self) -> &str {
        match &self.query_state {
            QueryState::Loading { domain }
            | QueryState::Querying { domain }
            | QueryState::Done { domain, .. }
            | QueryState::Error { domain, .. } => domain,
            QueryState::Idle => "",
        }
    }

    /// Rebuild the category map when the domain changes.
    fn rebuild_category_map(&mut self, domain_name: &Name) {
        self.category_map.clear();
        for entry in &self.default_entries {
            if entry.subdomain.is_empty() {
                self.category_map.insert((domain_name.to_string(), entry.record_type), Category::Apex);
            } else if let Ok(sub) = Name::from_str(entry.subdomain) {
                if let Ok(full) = sub.append_domain(domain_name) {
                    self.category_map.insert((full.to_string(), entry.record_type), entry.category);
                }
            }
        }
    }

    fn push_history(&mut self) {
        let entry = HistoryEntry {
            domain: self.current_domain().to_string(),
            input: self.input.clone(),
            query_state: self.query_state.clone(),
            lookups: self.lookups.clone(),
            rows: self.rows.clone(),
            selected_index: self.table_state.selected(),
            stats_data: self.stats_data.clone(),
            whois_data: self.whois_data.clone(),
            whois_error: self.whois_error.clone(),
            lint_results: self.lint_results.clone(),
            discovery_state: self.discovery_state.clone(),
            category_map: self.category_map.clone(),
            active_categories: self.active_categories.clone(),
            filter: self.filter.clone(),
            filter_input: self.filter_input.clone(),
            batch_progress: self.batch_progress,
        };
        if self.history.len() >= 50 {
            self.history.remove(0);
        }
        self.history.push(entry);
    }

    fn pop_history(&mut self) {
        if let Some(entry) = self.history.pop() {
            self.input = entry.input;
            self.cursor_pos = self.input.len();
            self.query_state = entry.query_state;
            self.lookups = entry.lookups;
            self.rows = entry.rows;
            self.stats_data = entry.stats_data;
            self.whois_data = entry.whois_data;
            self.whois_error = entry.whois_error;
            self.lint_results = entry.lint_results;
            self.discovery_state = entry.discovery_state;
            self.category_map = entry.category_map;
            self.active_categories = entry.active_categories;
            self.filter = entry.filter;
            self.filter_input = entry.filter_input;
            self.filter_cursor_pos = self.filter_input.len();
            self.batch_progress = entry.batch_progress;
            self.table_state.select(entry.selected_index);
        }
    }

    fn drill_to(&mut self, domain: String) {
        self.push_history();

        // Abort existing tasks
        if let Some(handle) = self.dns_task.take() {
            handle.abort();
        }
        for handle in self.discovery_tasks.drain(..) {
            handle.abort();
        }
        self.resolver_group = None;

        self.input = domain.clone();
        self.cursor_pos = domain.len();
        self.mode = Mode::Normal;
        self.query_generation += 1;
        self.query_state = QueryState::Loading {
            domain,
        };
        self.rows.clear();
        self.lookups = None;
        self.batch_progress = (0, 0);
        self.table_state.select(None);
        self.filter = None;
        self.filter_error = None;
        self.filter_input.clear();
        self.filter_cursor_pos = 0;
        self.whois_data = None;
        self.whois_error = None;
        self.whois_loading = false;
        self.lint_results = None;
        self.stats_data = None;
        self.discovery_state = None;
        self.category_map.clear();
    }

    fn rebuild_rows(&mut self) {
        if self.lookups.is_none() {
            return;
        }
        let domain = self.current_domain().to_string();
        if domain.is_empty() {
            return;
        }

        // Build lookup table: (full_name, record_type) -> category
        // Ensure FQDN so to_string() matches DNS response names (which are always FQDN)
        let fqdn = if domain.ends_with('.') { domain.clone() } else { format!("{domain}.") };
        let domain_name = match Name::from_str(&fqdn) {
            Ok(n) => n,
            Err(_) => return,
        };

        // Rebuild category map only if it's empty (new domain)
        if self.category_map.is_empty() {
            self.rebuild_category_map(&domain_name);
        }

        let lookups = self.lookups.as_ref().unwrap();

        let mut seen = HashSet::new();
        let mut rows = Vec::new();

        for lookup in lookups.iter() {
            let ns = lookup.name_server().to_string();
            for record in lookup.records() {
                let name_str = record.name().to_string();
                let rt = record.record_type();

                // Look up category for this record
                let category = self.category_map
                    .get(&(name_str.clone(), rt))
                    .copied()
                    .unwrap_or_else(|| {
                        // Check if this is a subdomain of the queried domain (discovered record)
                        if let Ok(record_name) = Name::from_str(&name_str) {
                            if domain_name.zone_of(&record_name) && record_name != domain_name {
                                return Category::Discovered;
                            }
                        }
                        Category::Apex
                    });

                // Apex and Discovered always included; others filtered by active categories
                if category != Category::Apex
                    && category != Category::Discovered
                    && !self.active_categories.contains(&category)
                {
                    continue;
                }

                // Dedup by (name, type, value)
                let value = format_rdata(record.data());
                let key = (name_str.clone(), rt, value.clone());
                if !seen.insert(key) {
                    continue;
                }

                let human_value = format_rdata_human(record.data());
                let drill_target = extract_drill_target(record.data());
                rows.push(RecordRow {
                    name: name_str,
                    record_type: rt,
                    ttl: record.ttl(),
                    value,
                    human_value,
                    nameserver: ns.clone(),
                    category,
                    drill_target,
                });
            }
        }

        rows.sort_by(|a, b| {
            category_ordinal(a.category)
                .cmp(&category_ordinal(b.category))
                .then_with(|| a.record_type.ordinal().cmp(&b.record_type.ordinal()))
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.value.cmp(&b.value))
        });

        // Apply regex filter
        if let Some(ref re) = self.filter {
            rows.retain(|row| {
                re.is_match(&row.name)
                    || re.is_match(&row.record_type.to_string())
                    || re.is_match(&row.value)
                    || re.is_match(&row.human_value)
            });
        }

        // Preserve selection if possible
        let prev_selected = self.table_state.selected();
        self.rows = rows;
        if self.rows.is_empty() {
            self.table_state.select(None);
        } else if let Some(i) = prev_selected {
            self.table_state
                .select(Some(i.min(self.rows.len().saturating_sub(1))));
        }

        // Update record count in Done state
        if let QueryState::Done { record_count, .. } = &mut self.query_state {
            *record_count = self.rows.len();
        }
    }
}

/// Extract a drillable hostname target from record data.
/// Returns `None` for record types without a hostname value (A, AAAA, TXT, etc.).
fn extract_drill_target(rdata: &RData) -> Option<String> {
    let name = match rdata {
        RData::CNAME(name) | RData::ANAME(name) | RData::NS(name) | RData::PTR(name) => {
            name.to_string()
        }
        RData::MX(mx) => mx.exchange().to_string(),
        RData::SRV(srv) => srv.target().to_string(),
        RData::SOA(soa) => soa.mname().to_string(),
        RData::SVCB(svcb) | RData::HTTPS(svcb) => {
            let t = svcb.target_name().to_string();
            if t == "." { return None; }
            t
        }
        RData::NAPTR(naptr) => {
            let t = naptr.replacement().to_string();
            if t == "." { return None; }
            t
        }
        _ => return None,
    };
    let name = name.trim_end_matches('.').to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn record_type_info(rt: RecordType) -> Option<(&'static str, &'static str, Option<&'static str>)> {
    mhost::app::common::record_type_info::find(&rt.to_string())
        .map(|info| (info.summary, info.detail, info.rfc))
}

/// Format a raw nameserver string like `udp:8.8.8.8:53,name=Google` into
/// a human-friendly form like `Google (udp, 8.8.8.8)`.
pub fn format_nameserver_human(raw: &str) -> String {
    // Split off key=value options after first comma
    let (addr_part, opts) = raw.split_once(',').unwrap_or((raw, ""));
    let name = opts
        .split(',')
        .find_map(|kv| kv.strip_prefix("name="))
        .unwrap_or("");

    // addr_part is like "udp:8.8.8.8:53" or "https:dns.google:443"
    let parts: Vec<&str> = addr_part.splitn(3, ':').collect();
    let (protocol, host) = if parts.len() >= 2 {
        (parts[0], parts[1])
    } else {
        return raw.to_string();
    };

    if name.is_empty() {
        format!("{host} ({protocol})")
    } else {
        format!("{name} ({protocol}, {host})")
    }
}
