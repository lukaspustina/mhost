use anyhow::{Context, Result};
use std::path::Path;
use std::slice::Iter;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tracing::trace;

use crate::{IntoName, Name};

static DEFAULT_WORD_LIST: &str = r#"admin
_amazonses
admin
alpha
api
app
assets
auth
aws
beta
blog
chat
cms
confluence
ct
dashboard
dev
development
dialin
download
epaper
exchange
external
foto
ftp
gatekeeper
gateway
git
gitlab
gw
hq
id
in
intern
iphone
jobs
ldap
listserv
login
m
mail
mailhost
meet
mobi
mx
newsletter
ns
presse
public
radio
redirector
relay
reporting
rss
sales
sftp
shop
smtp
smtp01
smtp02
smtp1
smtp2
special
sso
staging
static
status
support
svn
test
ticket
tp
tr
update
upload
web
wopi
www
www-server
www-test
wwwtest
zendesk1
zendeskverification"#;

#[derive(Debug)]
pub struct Wordlist {
    words: Vec<Name>,
}

impl Wordlist {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Wordlist> {
        let file = File::open(path).await?;
        let mut buf_reader = BufReader::new(file);

        let mut words = Vec::new();
        loop {
            let mut buffer = String::new();
            let len = buf_reader.read_line(&mut buffer).await?;
            if len == 0 {
                break;
            }
            if Wordlist::is_comment(&buffer) {
                continue;
            }
            trace!("Parsing wordlist item '{}'.", buffer);
            let name: Name = buffer
                .trim_end() // BufReader::read_line returns trainling line break
                .into_name()
                .context("failed to read word list because of invalid domain name")?;
            words.push(name);
        }

        Ok(Wordlist { words })
    }

    fn is_comment(line: &str) -> bool {
        line.starts_with("//") || line.starts_with("#")
    }

    pub fn from_str(data: &str) -> Result<Wordlist> {
        let mut words = Vec::new();

        for line in data.lines() {
            if Wordlist::is_comment(&line) {
                continue;
            }
            trace!("Parsing wordlist item '{}'.", line);
            let name: Name = line
                .into_name()
                .context("failed to read word list because of invalid domain name")?;
            words.push(name);
        }

        Ok(Wordlist { words })
    }

    pub fn default() -> Result<Wordlist> {
        Wordlist::from_str(DEFAULT_WORD_LIST)
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> Iter<Name> {
        self.words.iter()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.words.len()
    }
}

impl IntoIterator for Wordlist {
    type Item = Name;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.words.into_iter()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use spectral::prelude::*;

    #[tokio::test]
    async fn read_from_file_5000() {
        crate::utils::tests::logging::init();
        let path = "contrib/subdomains-top1mil-5000.txt";

        let wordlist = Wordlist::from_file(path).await;

        asserting("Wordlist with 5000 elements loaded from file")
            .that(&wordlist)
            .is_ok()
            .map(|x| &x.words)
            .has_length(5000)
    }

    #[tokio::test]
    async fn read_from_file_20000() {
        crate::utils::tests::logging::init();
        let path = "contrib/subdomains-top1mil-20000.txt";

        let wordlist = Wordlist::from_file(path).await;

        asserting("Wordlist with 20000 elements loaded from file")
            .that(&wordlist)
            .is_ok()
            .map(|x| &x.words)
            .has_length(19998)
    }

    #[test]
    fn read_from_string() {
        crate::utils::tests::logging::init();
        let wordlist = Wordlist::from_str(&DEFAULT_WORD_LIST);

        asserting("Wordlist with 5000 elements loaded from string")
            .that(&wordlist)
            .is_ok()
            .map(|x| &x.words)
            .has_length(83)
    }
}
