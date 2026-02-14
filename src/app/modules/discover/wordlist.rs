// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::{Context, Result};
use std::path::Path;
use std::slice::Iter;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tracing::trace;

use crate::{IntoName, Name};

static DEFAULT_WORD_LIST: &str = r#"_amazonses
abuse
academy
account
accounts
accounting
ad
admin
admin1
admin2
adminer
alertmanager
alpha
analytics
ansible
api
api-docs
api-gateway
api1
api2
app
app1
app2
apps
archive
argo
assets
auth
auth0
autodiscover
autoconfig
aws
azure
backend
backup
backup1
backup2
bastion
beta
billing
bitbucket
blog
board
box
build
bulk
cache
cache1
calendar
canary
careers
cdn
cdn1
cdn2
chat
checkout
ci
citrix
clickhouse
client
cloud
cluster
cms
cockpit
code
community
confluence
connect
console
consul
contact
content
corp
cpanel
crm
cron
dashboard
data
database
db
db1
db2
db3
dc
demo
deploy
dev
dev1
dev2
development
devops
dhcp
dialin
direct
directory
dmz
dns
dns1
dns2
dns3
docker
docs
download
downloads
edge
elastic
elasticsearch
email
env
erp
es
etcd
events
exchange
external
extranet
faq
feed
file
files
firewall
forum
ftp
ftp1
ftp2
fw
gallery
gateway
gcp
gerrit
git
gitea
github
gitlab
go
grafana
graphql
gw
harbor
haproxy
health
help
helpdesk
home
host
host1
host2
hosting
hq
hr
hub
iam
id
identity
images
img
imap
in
inbound
influxdb
info
infra
intern
internal
intranet
iot
it
jenkins
jira
jobs
jump
k8s
kafka
kb
keycloak
kibana
kong
kubernetes
lab
labs
landing
lb
lb1
lb2
ldap
legacy
link
linux
listserv
live
lms
loadbalancer
local
log
login
logstash
loki
m
mail
mail1
mail2
mail3
mailer
mailhost
manage
management
manager
marketing
marketplace
mattermost
media
meet
memcached
metrics
mfa
minio
mirror
mobi
mobile
mongo
mongodb
monitor
monitoring
mqtt
ms
mssql
mta
mx
mx1
mx2
mx3
mysql
nagios
nas
net
new
news
newsletter
next
nexus
nginx
noc
node
node1
node2
nomad
notes
ns
ns1
ns2
ns3
ns4
ntp
oauth
office
okta
old
openid
ops
oracle
order
orders
origin
outbound
outlook
owa
packages
panel
partner
partners
pay
payment
pbx
phpmyadmin
pki
platform
plesk
pop
pop3
portal
portainer
postgres
postgresql
preprod
preview
print
private
prod
production
prometheus
proxy
proxy1
proxy2
public
puppet
push
qa
queue
rabbitmq
radius
rancher
rdp
redis
redirect
redirector
redmine
registry
relay
relay1
relay2
remote
render
repo
reporting
rest
review
rocketchat
roundcube
router
rss
rt
s3
sales
saml
sandbox
scan
scheduler
search
secure
security
sentry
server
server1
server2
service
sftp
share
sharepoint
shop
signin
signup
sip
site
slack
smtp
smtp01
smtp02
smtp1
smtp2
sonar
sonarqube
splunk
sql
srv
ssh
ssl
sso
stage
staging
static
stats
status
storage
store
stream
streaming
support
survey
svn
syslog
teams
terminal
terraform
test
test1
test2
testing
ticket
tickets
time
tls
tools
traefik
training
tunnel
uat
update
upload
v1
v2
v3
vault
video
vm
voip
vpn
vpn1
vpn2
waf
wap
web
web1
web2
web3
webadmin
webdav
webmail
webmin
webproxy
wiki
wopi
workspace
wpad
www
www-server
www-test
www1
www2
www3
wwwtest
zabbix
zendesk1
zendeskverification
zookeeper"#;

#[derive(Debug)]
pub struct Wordlist {
    words: Vec<Name>,
}

impl Wordlist {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Wordlist> {
        let file = File::open(path).await?;
        let mut buf_reader = BufReader::new(file);

        let mut line_counter = 0;
        let mut words = Vec::new();
        loop {
            let mut buffer = String::new();
            let len = buf_reader.read_line(&mut buffer).await?;
            if len == 0 {
                break;
            }
            line_counter += 1;
            if Wordlist::is_comment(&buffer) {
                continue;
            }
            trace!("Parsing wordlist item '{}'.", buffer);
            let buffer = buffer.trim_end(); // BufReader::read_line returns trailing line break
            let name: Name = buffer.into_name().context(format!(
                "failed to read word list because of invalid domain name '{}' at line {}",
                buffer, line_counter
            ))?;
            words.push(name);
        }

        Ok(Wordlist { words })
    }

    fn is_comment(line: &str) -> bool {
        line.starts_with("//") || line.starts_with('#')
    }

    pub fn from_str(data: &str) -> Result<Wordlist> {
        let mut words = Vec::new();

        for line in data.lines() {
            if Wordlist::is_comment(line) {
                continue;
            }
            trace!("Parsing wordlist item '{}'.", line);
            let name: Name = line.into_name().context(format!(
                "failed to read word list because of invalid domain name '{}'",
                line
            ))?;
            words.push(name);
        }

        Ok(Wordlist { words })
    }

    pub fn default() -> Result<Wordlist> {
        Wordlist::from_str(DEFAULT_WORD_LIST)
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> Iter<'_, Name> {
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
        let wordlist = Wordlist::from_str(DEFAULT_WORD_LIST);

        asserting("Wordlist with 5000 elements loaded from string")
            .that(&wordlist)
            .is_ok()
            .map(|x| &x.words)
            .has_length(424)
    }
}
