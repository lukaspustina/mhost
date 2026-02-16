use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;

use mhost::app::common::ordinal::Ordinal;
use mhost::app::common::rdata_format::{format_rdata, format_rdata_human};
use mhost::app::common::resolver_args::ResolverArgs;
use mhost::app::common::subdomain_spec::{default_entries, Category};
use mhost::resolver::lookup::{LookupResult, Lookups};
use mhost::resolver::Error as ResolverError;
use mhost::services::whois::WhoisResponses;
use mhost::{Name, RecordType};
use ratatui::widgets::TableState;
use regex::RegexBuilder;

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
    }
}

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Popup {
    None,
    RecordDetail(usize),
    Help,
    Servers,
    Whois,
    Lints,
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
    OpenPopup,
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
}

pub struct App {
    pub resolver_args: ResolverArgs,
    pub mode: Mode,
    pub input: String,
    pub cursor_pos: usize,
    pub filter_input: String,
    pub filter_cursor_pos: usize,
    pub filter: Option<regex::Regex>,
    pub filter_error: bool,
    pub active_categories: HashSet<Category>,
    pub query_state: QueryState,
    pub rows: Vec<RecordRow>,
    pub table_state: TableState,
    pub should_quit: bool,
    pub popup: Popup,
    pub human_view: bool,
    pub batch_progress: (usize, usize),
    pub count_buffer: String,
    pub pending_g: bool,
    pub(crate) lookups: Option<Lookups>,
    /// Monotonically increasing query generation; used to discard stale DNS results.
    pub(crate) query_generation: u64,
    pub whois_data: Option<WhoisResponses>,
    pub whois_error: Option<String>,
    pub whois_scroll: u16,
    pub whois_line_count: u16,
    /// True while a WHOIS fetch is in progress.
    pub(crate) whois_loading: bool,
    /// Tracks which query generation a pending/completed WHOIS fetch belongs to,
    /// so stale results from a previous query can be discarded.
    pub(crate) whois_generation: u64,
    pub lint_results: Option<Vec<LintSection>>,
    pub lint_scroll: u16,
    pub lint_line_count: u16,
    pub show_stats: bool,
    pub stats_data: Option<StatsData>,
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
            filter_error: false,
            active_categories: DEFAULT_CATEGORIES.iter().copied().collect(),
            query_state: QueryState::Idle,
            rows: Vec::new(),
            table_state: TableState::default(),
            should_quit: false,
            popup: Popup::None,
            human_view: false,
            batch_progress: (0, 0),
            count_buffer: String::new(),
            pending_g: false,
            lookups: None,
            query_generation: 0,
            whois_data: None,
            whois_error: None,
            whois_scroll: 0,
            whois_line_count: 0,
            whois_loading: false,
            whois_generation: 0,
            lint_results: None,
            lint_scroll: 0,
            lint_line_count: 0,
            show_stats: false,
            stats_data: None,
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
        // Vi-count bookkeeping: on non-count actions, flush a single-digit buffer
        // as a category toggle, then clear state.
        match &action {
            Action::DigitPress(_) | Action::PressG | Action::PressCapG => {}
            _ => {
                if self.count_buffer.len() == 1 && !self.pending_g {
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
                self.pending_g = false;
            }
        }

        match action {
            Action::Quit => self.should_quit = true,

            Action::EnterInputMode => {
                self.mode = Mode::Input;
            }
            Action::ExitInputMode => {
                self.mode = Mode::Normal;
            }
            Action::EnterSearchMode => {
                self.filter_input = self.filter.as_ref().map_or(String::new(), |r| r.as_str().to_string());
                self.filter_cursor_pos = self.filter_input.len();
                self.filter_error = false;
                self.mode = Mode::Search;
            }
            Action::ExitSearchMode => {
                self.filter_error = false;
                self.mode = Mode::Normal;
            }
            Action::ApplyFilter => {
                let trimmed = self.filter_input.trim().to_string();
                if trimmed.is_empty() {
                    self.filter = None;
                    self.filter_error = false;
                } else {
                    match RegexBuilder::new(&trimmed).case_insensitive(true).build() {
                        Ok(re) => {
                            self.filter = Some(re);
                            self.filter_error = false;
                        }
                        Err(_) => {
                            self.filter_error = true;
                            return;
                        }
                    }
                }
                self.mode = Mode::Normal;
                self.rebuild_rows();
            }
            Action::ClearFilter => {
                self.filter = None;
                self.filter_error = false;
                self.filter_input.clear();
                self.filter_cursor_pos = 0;
                self.rebuild_rows();
            }
            Action::SubmitQuery => {
                let domain = self.input.trim().to_string();
                if !domain.is_empty() {
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
                    self.filter_error = false;
                    self.filter_input.clear();
                    self.filter_cursor_pos = 0;
                    self.whois_data = None;
                    self.whois_error = None;
                    self.whois_loading = false;
                    self.lint_results = None;
                    self.stats_data = None;
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
                self.count_buffer.push(c);
            }
            Action::PressG => {
                if self.pending_g {
                    // Second g: jump to line N or top
                    self.pending_g = false;
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
                    self.pending_g = true;
                }
            }
            Action::PressCapG => {
                self.pending_g = false;
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

            Action::OpenPopup => {
                if let Some(idx) = self.table_state.selected() {
                    self.popup = Popup::RecordDetail(idx);
                }
            }
            Action::OpenHelp => {
                self.popup = Popup::Help;
            }
            Action::OpenServers => {
                self.popup = Popup::Servers;
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
                match self.popup {
                    Popup::Lints => self.lint_scroll = self.lint_scroll.saturating_sub(1),
                    _ => self.whois_scroll = self.whois_scroll.saturating_sub(1),
                }
            }
            Action::PopupScrollDown => {
                match self.popup {
                    Popup::Lints => self.lint_scroll = self.lint_scroll.saturating_add(1).min(self.lint_line_count),
                    _ => self.whois_scroll = self.whois_scroll.saturating_add(1).min(self.whois_line_count),
                }
            }
            Action::PopupScrollPageUp => {
                match self.popup {
                    Popup::Lints => self.lint_scroll = self.lint_scroll.saturating_sub(10),
                    _ => self.whois_scroll = self.whois_scroll.saturating_sub(10),
                }
            }
            Action::PopupScrollPageDown => {
                match self.popup {
                    Popup::Lints => self.lint_scroll = self.lint_scroll.saturating_add(10).min(self.lint_line_count),
                    _ => self.whois_scroll = self.whois_scroll.saturating_add(10).min(self.whois_line_count),
                }
            }
            Action::PopupScrollHome => {
                match self.popup {
                    Popup::Lints => self.lint_scroll = 0,
                    _ => self.whois_scroll = 0,
                }
            }
            Action::PopupScrollEnd => {
                match self.popup {
                    Popup::Lints => self.lint_scroll = self.lint_line_count,
                    _ => self.whois_scroll = self.whois_line_count,
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

    pub fn current_domain(&self) -> &str {
        match &self.query_state {
            QueryState::Loading { domain }
            | QueryState::Querying { domain }
            | QueryState::Done { domain, .. }
            | QueryState::Error { domain, .. } => domain,
            QueryState::Idle => "",
        }
    }

    fn rebuild_rows(&mut self) {
        let Some(lookups) = &self.lookups else {
            return;
        };
        let domain = self.current_domain().to_string();
        if domain.is_empty() {
            return;
        }

        // Build lookup table: (full_name, record_type) -> category
        let domain_name = match Name::from_str(&domain) {
            Ok(n) => n,
            Err(_) => return,
        };
        let entries = default_entries();
        let mut category_map: HashMap<(String, RecordType), Category> = HashMap::new();
        for entry in &entries {
            if entry.subdomain.is_empty() {
                // Apex: key is the domain itself
                category_map.insert((domain_name.to_string(), entry.record_type), Category::Apex);
            } else if let Ok(sub) = Name::from_str(entry.subdomain) {
                if let Ok(full) = sub.append_domain(&domain_name) {
                    category_map.insert((full.to_string(), entry.record_type), entry.category);
                }
            }
        }

        let mut seen = HashSet::new();
        let mut rows = Vec::new();

        for lookup in lookups.iter() {
            let ns = lookup.name_server().to_string();
            for record in lookup.records() {
                let name_str = record.name().to_string();
                let rt = record.record_type();

                // Look up category for this record
                let category = category_map
                    .get(&(name_str.clone(), rt))
                    .copied()
                    .unwrap_or(Category::Apex);

                // Apex always included; non-Apex filtered by active categories
                if category != Category::Apex && !self.active_categories.contains(&category) {
                    continue;
                }

                // Dedup by (name, type, value)
                let value = format_rdata(record.data());
                let key = (name_str.clone(), rt, value.clone());
                if !seen.insert(key) {
                    continue;
                }

                let human_value = format_rdata_human(record.data());
                rows.push(RecordRow {
                    name: name_str,
                    record_type: rt,
                    ttl: record.ttl(),
                    value,
                    human_value,
                    nameserver: ns.clone(),
                    category,
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
