use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;

use mhost::app::common::ordinal::Ordinal;
use mhost::app::common::rdata_format::format_rdata;
use mhost::app::common::resolver_args::ResolverArgs;
use mhost::app::modules::domain_lookup::subdomain_spec::{default_entries, Category};
use mhost::resolver::lookup::Lookups;
use mhost::resources::rdata::parsed_txt::{Mechanism, Modifier, ParsedTxt, Qualifier, Word};
use mhost::{Name, RecordType};
use ratatui::widgets::TableState;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Input,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    pub nameserver: String,
    pub category: Category,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Popup {
    None,
    RecordDetail(usize),
    Help,
    Servers,
}

pub enum Action {
    Quit,
    EnterInputMode,
    ExitInputMode,
    SubmitQuery,
    InputChar(char),
    InputBackspace,
    InputLeft,
    InputRight,
    InputHome,
    InputEnd,
    InputDeleteWord,
    ToggleCategory(Category),
    SelectAll,
    SelectNone,
    ToggleHumanView,
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    Home,
    End,
    OpenPopup,
    OpenHelp,
    OpenServers,
    ClosePopup,
    DigitPress(char),
    PressG,
    PressCapG,
    DnsBatch { lookups: Lookups, completed: usize, total: usize },
    DnsComplete(Duration),
    DnsError(String),
}

pub struct App {
    pub resolver_args: ResolverArgs,
    pub mode: Mode,
    pub input: String,
    pub cursor_pos: usize,
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
}

impl App {
    pub fn new(resolver_args: ResolverArgs) -> Self {
        Self {
            resolver_args,
            mode: Mode::Normal,
            input: String::new(),
            cursor_pos: 0,
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
            Action::SubmitQuery => {
                let domain = self.input.trim().to_string();
                if !domain.is_empty() {
                    self.mode = Mode::Normal;
                    self.query_state = QueryState::Loading {
                        domain: domain.clone(),
                    };
                    self.rows.clear();
                    self.lookups = None;
                    self.batch_progress = (0, 0);
                    self.table_state.select(None);
                }
            }

            Action::InputChar(c) => {
                self.input.insert(self.cursor_pos, c);
                self.cursor_pos += c.len_utf8();
            }
            Action::InputBackspace => {
                if self.cursor_pos > 0 {
                    let prev = self.input[..self.cursor_pos]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.input.drain(prev..self.cursor_pos);
                    self.cursor_pos = prev;
                }
            }
            Action::InputLeft => {
                if self.cursor_pos > 0 {
                    self.cursor_pos = self.input[..self.cursor_pos]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            Action::InputRight => {
                if self.cursor_pos < self.input.len() {
                    self.cursor_pos = self.input[self.cursor_pos..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.cursor_pos + i)
                        .unwrap_or(self.input.len());
                }
            }
            Action::InputHome => {
                self.cursor_pos = 0;
            }
            Action::InputEnd => {
                self.cursor_pos = self.input.len();
            }
            Action::InputDeleteWord => {
                if self.cursor_pos > 0 {
                    let before = &self.input[..self.cursor_pos];
                    let new_pos = before
                        .trim_end()
                        .rfind(|c: char| c.is_whitespace())
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    self.input.drain(new_pos..self.cursor_pos);
                    self.cursor_pos = new_pos;
                }
            }

            Action::ToggleCategory(cat) => {
                if self.active_categories.contains(&cat) {
                    self.active_categories.remove(&cat);
                } else {
                    self.active_categories.insert(cat);
                }
                self.rebuild_rows();
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
            Action::ClosePopup => {
                self.popup = Popup::None;
            }

            Action::DnsBatch { lookups, completed, total } => {
                self.batch_progress = (completed, total);
                match self.lookups.take() {
                    Some(existing) => self.lookups = Some(existing.merge(lookups)),
                    None => self.lookups = Some(lookups),
                }
                self.rebuild_rows();
                if !self.rows.is_empty() && self.table_state.selected().is_none() {
                    self.table_state.select(Some(0));
                }
            }
            Action::DnsComplete(elapsed) => {
                let server_count = self.lookups.as_ref().map_or(0, |lookups| {
                    let mut servers = std::collections::HashSet::new();
                    for lookup in lookups.iter() {
                        servers.insert(format!("{}", lookup.name_server()));
                    }
                    servers.len()
                });
                // Count total unique records (before category filtering)
                let total_record_count = self.lookups.as_ref().map_or(0, |lookups| {
                    let mut seen = std::collections::HashSet::new();
                    for lookup in lookups.iter() {
                        for record in lookup.records() {
                            let key = (
                                record.name().to_string(),
                                record.record_type(),
                                format!("{:?}", record.data()),
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
            Action::DnsError(message) => {
                let domain = self.current_domain().to_string();
                self.query_state = QueryState::Error { domain, message };
                self.batch_progress = (0, 0);
            }
        }
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

        let mut seen = std::collections::HashSet::new();
        let mut rows = Vec::new();

        for lookup in lookups.iter() {
            let ns = format!("{}", lookup.name_server());
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

                rows.push(RecordRow {
                    name: name_str,
                    record_type: rt,
                    ttl: record.ttl(),
                    value,
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

pub fn format_rdata_human(row: &RecordRow) -> String {
    let value = &row.value;
    match row.record_type {
        RecordType::MX => {
            let parts: Vec<&str> = value.splitn(2, ' ').collect();
            if parts.len() == 2 {
                format!("Priority: {}\nExchange: {}", parts[0], parts[1])
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::SOA => {
            let parts: Vec<&str> = value.splitn(7, ' ').collect();
            if parts.len() == 7 {
                format!(
                    "Primary NS: {}\nContact: {}\nSerial: {}\nRefresh: {}\nRetry: {}\nExpire: {}\nMinimum TTL: {}",
                    parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                )
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::SRV => {
            let parts: Vec<&str> = value.splitn(4, ' ').collect();
            if parts.len() == 4 {
                format!(
                    "Priority: {}\nWeight: {}\nPort: {}\nTarget: {}",
                    parts[0], parts[1], parts[2], parts[3]
                )
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::CAA => {
            let parts: Vec<&str> = value.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let critical = parts[0] == "128";
                let tag = parts[1];
                let raw_value = parts[2].trim_matches('"');
                let critical_suffix = if critical { " (critical)" } else { "" };
                let description = match (tag, raw_value) {
                    ("issue", v) if v.is_empty() || v == ";" => "no CA is allowed to issue certificates".to_string(),
                    ("issue", v) => format!("allow {v} to issue certificates"),
                    ("issuewild", v) if v.is_empty() || v == ";" => "no CA is allowed to issue wildcard certificates".to_string(),
                    ("issuewild", v) => format!("allow {v} to issue wildcard certificates"),
                    ("iodef", v) => format!("report policy violations to {v}"),
                    (t, v) => format!("{t} {v}"),
                };
                format!("Policy: {description}{critical_suffix}")
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::SVCB | RecordType::HTTPS => {
            let parts: Vec<&str> = value.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                let mut s = format!("Priority: {}\nTarget: {}", parts[0], parts[1]);
                if parts.len() == 3 {
                    s.push_str(&format!("\nParams: {}", parts[2]));
                }
                s
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::TLSA => {
            let parts: Vec<&str> = value.splitn(4, ' ').collect();
            if parts.len() == 4 {
                format!(
                    "Usage: {}\nSelector: {}\nMatching: {}\nData: {}",
                    parts[0], parts[1], parts[2], parts[3]
                )
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::SSHFP => {
            let parts: Vec<&str> = value.splitn(3, ' ').collect();
            if parts.len() == 3 {
                format!(
                    "Algorithm: {}\nFingerprint Type: {}\nFingerprint: {}",
                    parts[0], parts[1], parts[2]
                )
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::NAPTR => {
            let parts: Vec<&str> = value.splitn(6, ' ').collect();
            if parts.len() == 6 {
                format!(
                    "Order: {}\nPreference: {}\nFlags: {}\nServices: {}\nRegexp: {}\nReplacement: {}",
                    parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                )
            } else {
                format!("Value: {value}")
            }
        }
        RecordType::TXT => match ParsedTxt::from_str(value) {
            Ok(ParsedTxt::Spf(spf)) => {
                let mut lines = vec![
                    format!("Type: SPF"),
                    format!("Version: {}", spf.version()),
                ];
                for word in spf.words() {
                    match word {
                        Word::Word(q, mechanism) => {
                            let qualifier = match q {
                                Qualifier::Pass => "Pass",
                                Qualifier::Neutral => "Neutral",
                                Qualifier::Softfail => "Softfail",
                                Qualifier::Fail => "Fail",
                            };
                            let mechanism_str = match mechanism {
                                Mechanism::All => "all".to_string(),
                                Mechanism::A { domain_spec, cidr_len } => {
                                    let mut s = "a".to_string();
                                    if let Some(d) = domain_spec { s = format!("a:{d}"); }
                                    if let Some(c) = cidr_len { s = format!("{s}/{c}"); }
                                    s
                                }
                                Mechanism::IPv4(ip) => format!("ip4:{ip}"),
                                Mechanism::IPv6(ip) => format!("ip6:{ip}"),
                                Mechanism::MX { domain_spec, cidr_len } => {
                                    let mut s = "mx".to_string();
                                    if let Some(d) = domain_spec { s = format!("mx:{d}"); }
                                    if let Some(c) = cidr_len { s = format!("{s}/{c}"); }
                                    s
                                }
                                Mechanism::PTR(d) => match d {
                                    Some(d) => format!("ptr:{d}"),
                                    None => "ptr".to_string(),
                                },
                                Mechanism::Exists(d) => format!("exists:{d}"),
                                Mechanism::Include(d) => format!("include:{d}"),
                            };
                            lines.push(format!("{qualifier}: {mechanism_str}"));
                        }
                        Word::Modifier(modifier) => match modifier {
                            Modifier::Redirect(d) => lines.push(format!("Redirect: {d}")),
                            Modifier::Exp(d) => lines.push(format!("Exp: {d}")),
                        },
                    }
                }
                lines.join("\n")
            }
            Ok(ParsedTxt::Dmarc(dmarc)) => {
                let mut lines = vec![
                    format!("Type: DMARC"),
                    format!("Policy: {}", dmarc.policy()),
                ];
                if let Some(sp) = dmarc.subdomain_policy() { lines.push(format!("Subdomain Policy: {sp}")); }
                if let Some(rua) = dmarc.rua() { lines.push(format!("RUA: {rua}")); }
                if let Some(ruf) = dmarc.ruf() { lines.push(format!("RUF: {ruf}")); }
                if let Some(adkim) = dmarc.adkim() { lines.push(format!("DKIM Alignment: {adkim}")); }
                if let Some(aspf) = dmarc.aspf() { lines.push(format!("SPF Alignment: {aspf}")); }
                if let Some(pct) = dmarc.pct() { lines.push(format!("Percentage: {pct}")); }
                if let Some(fo) = dmarc.fo() { lines.push(format!("Failure Options: {fo}")); }
                if let Some(ri) = dmarc.ri() { lines.push(format!("Report Interval: {ri}")); }
                lines.join("\n")
            }
            Ok(ParsedTxt::MtaSts(mta_sts)) => {
                format!("Type: MTA-STS\nVersion: {}\nID: {}", mta_sts.version(), mta_sts.id())
            }
            Ok(ParsedTxt::TlsRpt(tls_rpt)) => {
                format!("Type: TLS-RPT\nVersion: {}\nRUA: {}", tls_rpt.version(), tls_rpt.rua())
            }
            Ok(ParsedTxt::Bimi(bimi)) => {
                let mut lines = vec![
                    format!("Type: BIMI"),
                    format!("Version: {}", bimi.version()),
                ];
                if let Some(logo) = bimi.logo() { lines.push(format!("Logo: {logo}")); }
                if let Some(authority) = bimi.authority() { lines.push(format!("Authority: {authority}")); }
                lines.join("\n")
            }
            Ok(ParsedTxt::DomainVerification(dv)) => {
                format!("Type: Verification\nVerifier: {}\nScope: {}\nID: {}", dv.verifier(), dv.scope(), dv.id())
            }
            Err(_) => format!("Value: {value}"),
        }
        RecordType::HINFO => {
            format!("Value: {value}")
        }
        RecordType::DNSKEY => {
            let mut tag = "";
            let mut algo = "";
            let mut flags = "";
            for part in value.split_whitespace() {
                if let Some(v) = part.strip_prefix("tag=") {
                    tag = v;
                } else if let Some(v) = part.strip_prefix("algo=") {
                    algo = v;
                } else if let Some(v) = part.strip_prefix("flags=") {
                    flags = v;
                }
            }
            format!("Flags: {flags}\nAlgorithm: {algo}\nKey Tag: {tag}")
        }
        RecordType::DS => {
            let mut tag = "";
            let mut algo = "";
            let mut digest = "";
            for part in value.split_whitespace() {
                if let Some(v) = part.strip_prefix("tag=") {
                    tag = v;
                } else if let Some(v) = part.strip_prefix("algo=") {
                    algo = v;
                } else if let Some(v) = part.strip_prefix("digest=") {
                    digest = v;
                }
            }
            format!("Key Tag: {tag}\nAlgorithm: {algo}\nDigest Type: {digest}")
        }
        RecordType::RRSIG => {
            let parts: Vec<&str> = value.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let tag = parts[2].strip_prefix("tag=").unwrap_or(parts[2]);
                format!(
                    "Type Covered: {}\nAlgorithm: {}\nKey Tag: {}",
                    parts[0], parts[1], tag
                )
            } else {
                format!("Value: {value}")
            }
        }
        _ => format!("Value: {value}"),
    }
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
