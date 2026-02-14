# ![mhost](docs/images/logo.png) mhost

A modern take on the classic `host` DNS lookup utility including an easy to use and very fast Rust lookup library.

[![CI build](https://github.com/lukaspustina/mhost/workflows/CI%20build/badge.svg)](https://github.com/lukaspustina/mhost/actions/) [![mhost on crates.io](http://meritbadge.herokuapp.com/mhost)](https://crates.io/crates/mhost) [![Documentation on docs.rs](https://docs.rs/mhost/badge.svg)](https://docs.rs/mhost) [![GitHub release](https://img.shields.io/github/release/lukaspustina/mhost.svg)](https://github.com/lukaspustina/mhost/releases) ![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg) ![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)

## Features

-   `mhost` is very fast and uses multiple DNS servers concurrently and aggregates all results for more reliable lookups.

-   `mhost` supports classic DNS over UDP and TCP as well as modern DNS over TLS (DoT) and HTTP (DoH).

-   `mhost` supports 20 DNS record types including A, AAAA, CAA, CNAME, HINFO, HTTPS, MX, NAPTR, NS, OPENPGPKEY, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, and DNSSEC records.

-   `mhost` presents results in an easy, human readable format or as JSON for post-processing.

-   `mhost` discovers host names and subdomains using 10+ strategies: wordlists, Certificate Transparency logs, SRV probing, TXT record mining, zone transfers, NSEC walking, subdomain permutation, reverse DNS, and recursive discovery.

-   `mhost` uses 10 lints to validate DNS configurations against RFCs: SOA, NS, CNAME, MX, SPF, DMARC, CAA, TTL consistency, DNSSEC, and HTTPS/SVCB.

-   `mhost` can look up a domain's full DNS profile in one command with `domain-lookup`, querying apex records and ~40 well-known subdomains (email auth, SRV services, DANE/TLSA, etc.).

-   `mhost` ships with 84 predefined nameserver configurations across 6 providers (Cloudflare, Google, Quad9, Mullvad, Wikimedia, DNS4EU) using unfiltered endpoints.

-   `mhost` offers an easy to use Rust library so you can use the same lookup capabilities in your own project.

For details see sections [Use Cases](#Use-Cases) and [Documentation](#documentation) of this Readme.

## Quick Start

1.  Install `mhost` -- see below for [installation instructions](#installation).

2.  Run `mhost -p l --all -w github.com` and you've just asked 16 name servers for all available DNS records of *github.com* in 34 ms. And in addition you get the WHOIS information for GitHub's subnet. ![Multi lookup for all available records of github.com.](docs/images/multi-lookup-all-records-github.png)

3.  Run `mhost -q -p --output json l --all -w github.com  | jq '.lookups[] | .result.Response.records[]? | select(.type == "A") | .data.A'` and get all IPv4 addresses.

4.  Set shell alias `alias host=mhost l` to replace your system's `host` command.

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Use Cases](#use-cases)
  - [Just lookup an IP address](#just-lookup-an-ip-address)
    - [Just lookup an IP address, using more than just your local name servers](#just-lookup-an-ip-address-using-more-than-just-your-local-name-servers)
  - [Just lookup an IP address, using even more than just your local name servers](#just-lookup-an-ip-address-using-even-more-than-just-your-local-name-servers)
  - [Just lookup an IP address, using UDP, TCP, DoT, and DoH](#just-lookup-an-ip-address-using-udp-tcp-dot-and-doh)
  - [Look up a domain's full DNS profile](#look-up-a-domains-full-dns-profile)
  - [Discover a domain](#discover-a-domain)
  - [Check your name server configuration](#check-your-name-server-configuration)
  - [Get info about record types](#get-info-about-record-types)
- [Installation](#installation)
  - [Docker](#docker)
  - [Homebrew](#homebrew)
  - [Debian and Ubuntu](#debian-and-ubuntu)
  - [Redhat and Fedora](#redhat-and-fedora)
  - [For Rust Developers](#for-rust-developers)
  - [From Source](#from-source)
- [Documentation](#documentation)
  - [General Options](#general-options)
  - [Main Commands](#main-commands)
    - [Lookup](#lookup)
    - [Domain Lookup](#domain-lookup)
    - [Discover](#discover)
    - [Check](#check)
  - [Helper Commands](#helper-commands)
    - [Info](#info)
    - [Server Lists](#server-lists)
  - [Predefined Nameservers](#predefined-nameservers)
  - [Supported Record Types](#supported-record-types)
  - [Architecture Design Records](#architecture-design-records)
- [Changelog](#changelog)
- [Limitations](#limitations)
- [Thanks](#thanks)
- [Postcardware](#postcardware)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Use Cases

### Just lookup an IP address

```sh
$ mhost l github.com
```

![Default lookup for github.com.](docs/images/default-lookup-github.png)

In this run, all default settings are applied. Especially, `most` uses only the local system's name servers and queries only the default record types.

#### Just lookup an IP address, using more than just your local name servers

```sh
$ mhost -p l github.com
```

![Default lookup with predefined servers for github.com.](docs/images/default-lookup-predefined-servers-github.png)

See, there're more answers than before!

`-p` add public name servers that `mhost` predefines for your convenience. By default, only the UDP is used to contact the predefined name servers. You can control this behaviour using `--predefined-filter` and filter for UDP, TCP, DoT, DoH. `--list-predefined` show all available predefined name servers.

### Just lookup an IP address, using even more than just your local name servers

```sh
$ mhost server-lists public-dns -o servers.txt
$ mhost --limit 6000 --max-concurrent-servers 1000 --timeout 1 -f servers.txt l www.github.com
```

![Default lookup with servers list for github.com.](docs/images/default-lookup-servers-list-github.png)

See, there're even more answers than before!

The first command downloads a list of public available name servers that are maintained by the [Public DNS](https://public-dns.info) community. Usually only a subset of these are reachable, but it still a large set of active name servers.

The second command uses the name servers list from before and queries all of them concurrently. These settings are very aggressive and highly stresses your internet connection. `mhost` default settings are set much more cautiously.

### Just lookup an IP address, using UDP, TCP, DoT, and DoH

```sh
$ mhost -s 1.1.1.1 -s tcp:1.1.1.1 -s tls:1.1.1.1:853,tls_auth_name=cloudflare-dns.com -s https:1.1.1.1:443,tls_auth_name=cloudflare-dns.com,name=Cloudflare -p l github.com
```

As already mentioned before, `mhost` supports DNS queries over UDP, TCP, DNS over TLS (DoT), as well as DNS over HTTPS (DoH). In the above example, `mhost` uses all four protocols to query Cloudflare's name servers.

This command also shows the syntax for name server specification, which in general is `protocol:<host name | ip address>:port,tls_auth_name=hostname,name=human-readable-name`.

![Default lookup with all protocols for github.com.](docs/images/default-lookup-all-protocols-github.png)

### Look up a domain's full DNS profile

```sh
$ mhost -p domain-lookup example.com
```

The `domain-lookup` command queries a domain's apex records and ~40 well-known subdomains in a single operation. This includes email authentication records (DMARC, MTA-STS, TLS-RPT, BIMI), SRV records for common services (email, calendar, communication), TLSA/DANE records, and more.

```sh
$ mhost -p domain-lookup --all example.com
```

Use `--all` to include extended well-known subdomains (~65 total entries), covering additional SRV services, modern protocols, and verification/metadata records.

### Discover a domain

Sometimes you want to know which host names and subdomains a domain has. `mhost` offers a comprehensive discovery engine with 10+ strategies. Please mind, that `mhost` only uses DNS specific discovery methods. If you want even deeper discoveries using Google, Shodan etc. there are other tools available.

```sh
$ mhost -p d github.com -p
```

This command uses the predefined name servers to discover the GitHub domain. The `-s` reduces all discovered names to real subdomains of `github.com.`.

![Discover github.com.](docs/images/discover-github.png)

Discovery strategies include:
- **Wordlist lookups** -- brute-force subdomains using a built-in wordlist of 424 entries (or a custom wordlist via `-w`)
- **Certificate Transparency logs** -- query crt.sh for issued certificates (disable with `--no-ct-logs`)
- **SRV service probing** -- probe common SRV service records (email, SIP, XMPP, etc.)
- **TXT record mining** -- extract domain names referenced in TXT records
- **Zone transfer (AXFR)** -- attempt DNS zone transfers
- **NSEC walking** -- enumerate zone contents via NSEC records
- **Subdomain permutation** -- generate permutations of discovered subdomains
- **Reverse DNS** -- reverse-lookup discovered IP addresses
- **Recursive discovery** -- apply discovery recursively on found subdomains (controlled via `--depth`)
- **Wildcard detection** -- detect wildcard DNS records using random subdomain probes

You can go one more step and explore the autonomous systems GitHub uses. In order to discover those, you can use the following commands:

```sh
$ mhost -p l --all -w github.com
$ mhost -p l --all 140.82.121.0/24
```

![Discover AS of github.com.](docs/images/discover-as-github.png)

### Check your name server configuration

```sh
$ mhost -p c github.com -p
```

![Check github.com.](docs/images/check-github.png)

The `check` command validates a domain's DNS configuration using 10 lints:
- **SOA** -- validates Start of Authority records
- **NS** -- checks NS delegation
- **CNAME** -- validates CNAME usage
- **MX** -- checks MX record hygiene
- **SPF** -- validates SPF records
- **DMARC** -- validates DMARC policies
- **CAA** -- checks Certificate Authority Authorization records
- **TTL** -- verifies TTL consistency
- **DNSSEC** -- validates DNSSEC configuration
- **HTTPS/SVCB** -- checks HTTPS and SVCB service binding records

Each lint can be individually disabled (e.g., `--no-dmarc`, `--no-caa`, `--no-dnssec`).

### Get info about record types

```sh
$ mhost info           # List all supported types
$ mhost info MX        # Show details about MX records
$ mhost info SPF       # Show details about SPF TXT sub-type
$ mhost info _dmarc    # Show details about the _dmarc well-known subdomain
```

The `info` command shows information about DNS record types, TXT sub-types, and well-known subdomains.

## Installation

### Docker

If you want to give `mhost` a quick spin and just try it out without too much hassle, you might want to try the Docker image:

```sh
$ docker run lukaspustina/mhost:latest mhost l mhost.pustina.de
```

### Homebrew

```sh
$ brew install lukaspustina/mhost/mhost
```

### Debian and Ubuntu

You can find Debian packages on the [GitHub Release](https://github.com/lukaspustina/mhost/releases) page. Download the package as `mhost.deb` and the run

```sh
$ dpkg -i mhost.deb
```

### Redhat and Fedora

You can find RPM packages on the [GitHub Release](https://github.com/lukaspustina/mhost/releases) page. Download the package as `mhost.rpm` and the run

```sh
$ rpm -i mhost.rpm
```

### For Rust Developers

```sh
$ cargo install --features app mhost
```

### From Source

Please install Rust via [rustup](https://www.rustup.rs) and then run

```sh
$ git clone https://github.com/lukaspustina/mhost
$ cd mhost
$ make install
```

## Documentation

`mhost` has four main commands and two helper commands:

| Command | Description |
|---------|-------------|
| `lookup` (`l`) | Look up arbitrary DNS records of a domain name, IP address, or CIDR block |
| `domain-lookup` (`domain`) | Look up a domain's apex records and well-known subdomains in one operation |
| `discover` (`d`) | Discover host names and subdomains using multiple heuristics |
| `check` (`c`) | Validate DNS configuration using lints |
| `info` | Show information about DNS record types and well-known subdomains |
| `server-lists` | Download public nameserver lists |

### General Options

```plain
    --use-system-resolv-opt                 Uses options set in /etc/resolv.conf
    --no-system-nameservers                 Ignores nameservers from /etc/resolv.conf
-S, --no-system-lookups                     Ignores system nameservers for lookups
    --resolv-conf <FILE>                    Uses alternative resolv.conf file
    --ndots <NUMBER>                        Sets number of dots to qualify domain name as FQDN [default: 1]
    --search-domain <DOMAIN>                Sets the search domain to append if HOSTNAME has less than ndots dots
    --system-nameserver <IP ADDR>           Adds system nameserver for system lookups; only IP addresses allowed
-s, --nameserver <HOSTNAME | IP ADDR>       Adds nameserver for lookups
-p, --predefined                            Adds predefined nameservers for lookups
    --predefined-filter <PROTOCOL>          Filters predefined nameservers by protocol [default: udp]
                                            [possible values: udp, tcp, https, tls]
    --list-predefined                       Lists all predefined nameservers
-f, --nameservers-from-file <FILE>          Adds nameservers from file
    --limit <NUMBER>                        Sets max. number of nameservers to query [default: 100] (1-10000)
    --max-concurrent-servers <NUMBER>       Sets max. concurrent nameservers [default: 10] (1-100)
    --max-concurrent-requests <NUMBER>      Sets max. concurrent requests per nameserver [default: 5] (1-50)
    --retries <NUMBER>                      Sets number of retries if first lookup to nameserver fails [default: 0] (0-10)
    --timeout <TIMEOUT>                     Sets timeout in seconds for responses [default: 5] (1-300)
-m, --resolvers-mode <MODE>                 Sets resolvers lookup mode [default: multi]  [possible values: multi, uni]
    --wait-multiple-responses               Waits until timeout for additional responses from nameservers
    --continue-on-error                     Continues lookups even when nameservers return errors
    --continue-on-timeout                   Continues lookups even when nameservers time out
    --continue-on-all-errors                Continues lookups on all errors and timeouts from nameservers
-o, --output <FORMAT>                       Sets the output format for result presentation [default: summary]
                                            [possible values: json, summary]
    --output-options <OPTIONS>              Sets output options
    --show-errors                           Shows error counts
-q, --quiet                                 Does not print anything but results
    --no-color                              Disables colorful output
    --ascii                                 Uses only ASCII compatible characters for output
-v                                          Sets the level of verbosity
    --debug                                 Uses debug formatting for logging -- much more verbose
```

### Main Commands

#### Lookup

```plain
-t, --record-type <RECORD TYPE>    Sets record type to lookup, will be ignored in case of IP address lookup
                                   [default: A,AAAA,CNAME,MX]
                                   [possible values: A, AAAA, ANAME, ANY, CAA, CNAME, HINFO, HTTPS, MX, NAPTR,
                                    NULL, NS, OPENPGPKEY, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT]
    --all                          Enables lookups for all record types
-s, --service                      Parses ARG as service spec and set record type to SRV
-w, --whois                        Retrieves Whois information about A, AAAA, and PTR records

<DOMAIN NAME | IP ADDR | CIDR BLOCK [| SERVICE SPEC]>
        domain name, IP address, CIDR block, or, if -s, SERVICE SPEC, to lookup
        * DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de
        * IP ADDR may be any valid IPv4 or IPv4 address, e.g., 192.168.0.1
        * CIDR BLOCK may be any valid IPv4 or IPv6 subnet in CIDR notation, e.g., 192.168.0.1/24
            all valid IP addresses of a CIDR block will be queried for a reverse lookup
        * SERVICE SPEC may be specified by name, protocol, and domain name, delimited by colons.
          If protocol is omitted, tcp is assumed, e.g.,
            * dns:udp:example.com is _dns._udp.example.com
            * smtp:tcp:example.com is _smtp._tcp.example.com
            * smtp::example.com is _smtp._tcp.example.com
```

#### Domain Lookup

```plain
-p, --show-partial-results    Shows results after each lookup step
    --all                     Includes extended well-known subdomains (Tier 3+4, ~65 total entries)

<DOMAIN NAME>                 Domain name to look up, e.g., example.com
```

By default, queries ~40 well-known subdomain/record-type combinations including:
- **Apex records**: A, AAAA, MX, NS, SOA, CAA, HTTPS, TXT, CNAME, SVCB, NAPTR, SSHFP
- **Email authentication**: _dmarc (DMARC), _mta-sts (MTA-STS), _smtp._tls (TLS-RPT), default._bimi (BIMI)
- **Email SRV records**: _submission._tcp, _submissions._tcp, _imap._tcp, _imaps._tcp, _pop3s._tcp
- **TLS/DANE**: TLSA records for common ports (443, 25, 587, 993)
- **Communication services**: SIP, XMPP (with `--all`)
- **Calendar/Contacts**: CalDAV, CardDAV (with `--all`)

#### Discover

```plain
-p, --show-partial-results         Shows results after each lookup step
-w, --wordlist-from-file <FILE>    Uses wordlist from file
    --rnd-names-number <NUMBER>    Sets number of random domain names to generate for wildcard resolution check
                                   [default: 3] (1-20)
    --rnd-names-len <LEN>          Sets length of random domain names to generate for wildcard resolution check
                                   [default: 32] (8-128)
-s, --subdomains-only              Shows subdomains only omitting all other discovered names
    --no-ct-logs                   Skips Certificate Transparency log queries (external HTTP to crt.sh)
    --depth <N>                    Sets recursive discovery depth for found subdomains [default: 0] (0-3)
```

Discovery strategies (executed in order):
1. Standard DNS record lookups for the domain
2. Certificate Transparency log query via crt.sh
3. TXT record mining for referenced domain names
4. SRV service probing for common services
5. Wildcard detection using random subdomain probes
6. Zone transfer (AXFR) attempt
7. NSEC record walking
8. Wordlist-based subdomain brute force (424 built-in entries)
9. Subdomain permutation on discovered names
10. Recursive discovery on found subdomains (if `--depth` > 0)
11. Reverse DNS lookups on discovered IP addresses

#### Check

```plain
-p, --show-partial-results         Shows results after each check step
-i, --show-intermediate-lookups    Shows all lookups made during by all checks
    --no-cnames                    Does not run CNAME lints
    --no-soa                       Does not run SOA check
    --no-spf                       Does not run SPF check
    --no-dmarc                     Does not run DMARC check
    --no-ns                        Does not run NS delegation check
    --no-mx                        Does not run MX hygiene check
    --no-caa                       Does not run CAA check
    --no-ttl                       Does not run TTL sanity check
    --no-dnssec                    Does not run DNSSEC check
    --no-https-svcb                Does not run HTTPS/SVCB check
```

### Helper Commands

#### Info

```plain
[TOPIC]    Record type (A, AAAA, MX, ...), TXT sub-type (SPF, DMARC, ...), or
           well-known subdomain (_dmarc, _443._tcp, ...). Omit to list all supported types.
```

#### Server Lists

```plain
-o, --output-file <FILE>    Sets path to output file
<SERVER LIST SPEC>...
    SERVER LIST SPEC as <SOURCE>[:OPTIONS,...]
    * 'public-dns' with options - cf. https://public-dns.info
        '<top level country domain>': options select servers from that country
        Example: public-dns:de
    * 'opennic' with options; uses GeoIP to select servers - cf. https://www.opennic.org
        'anon' - only return servers with anonymized logs only; default is false
        'number=<1..>' - return up to 'number' servers; default is 10
        'reliability=<1..100> - only return server with reliability of 'reliability'% or more; default 95
        'ipv=<4|6|all> - return IPv4, IPv6, or both servers; default all
        Example: opennic:anon,number=10,ipv=4
```

### Predefined Nameservers

`mhost` ships with 84 predefined nameserver configurations across 6 providers. All use **unfiltered endpoints** (no content filtering or blocking). Each provider supports UDP, TCP, DoT, and DoH protocols.

| Provider | IPv4 Addresses | IPv6 Addresses | TLS/HTTPS Hostname |
|----------|---------------|---------------|-------------------|
| Cloudflare | 1.1.1.1, 1.0.0.1 | 2606:4700:4700::1111, ::1001 | cloudflare-dns.com |
| Google | 8.8.8.8, 8.8.4.4 | 2001:4860:4860::8888, ::8844 | dns.google |
| Quad9 | 9.9.9.10, 149.112.112.10 | 2620:fe::10, 2620:fe::fe:10 | dns10.quad9.net |
| Mullvad | 194.242.2.2, 193.19.108.2 | 2a07:e340::2 | dns.mullvad.net |
| Wikimedia | 185.71.138.138, 185.71.139.139 | 2001:67c:930::1, ::2 | wikimedia-dns.org |
| DNS4EU | 185.134.197.54, 185.134.196.54 | -- | unfiltered.joindns4.eu |

Use `--list-predefined` to see all configurations.

### Supported Record Types

| Record Type | Description |
|------------|-------------|
| A | IPv4 address |
| AAAA | IPv6 address |
| ANAME | ANAME / ALIAS record |
| ANY | Query all record types |
| CAA | Certification Authority Authorization |
| CNAME | Canonical name (alias) |
| HINFO | Host information |
| HTTPS | HTTPS service binding |
| MX | Mail exchange |
| NAPTR | Naming Authority Pointer |
| NS | Name server |
| NULL | Null record |
| OPENPGPKEY | OpenPGP public key |
| PTR | Pointer (reverse DNS) |
| SOA | Start of Authority |
| SRV | Service locator |
| SSHFP | SSH fingerprint |
| SVCB | Service binding |
| TLSA | TLS/DANE certificate association |
| TXT | Text record |

DNSSEC record types (DNSKEY, DS, RRSIG, NSEC, NSEC3, etc.) are also supported.

### Architecture Design Records

The subdirectory [docs/adr](docs/adr/) contains Architecture Design Records (ADRs) for this project. Record keeping has started during the project so not all decisions have been recorded. I still hope they will help everybody interested including me to understand the rational of design decisions.

## Changelog

Please see the [CHANGELOG](CHANGELOG.md) for a release history.

## Limitations

-   Currently `mhost` only supports class `IN`.

-   The Docker test environment only works completely on Linux due to [limitations](https://docs.docker.com/docker-for-mac/networking/#known-limitations-use-cases-and-workarounds) in Docker for macOS.

## Thanks

Thanks to [Benjamin Fry](https://github.com/bluejekyll) for his literally wonderful [Hickory DNS](https://github.com/hickory-dns/hickory-dns) (formerly Trust-DNS) server and the corresponding client library which does all the heavy DNS lifting of `mhost`.

## Postcardware

You're free to use `mhost`. If you find it useful, I would highly appreciate you sending me a postcard from your hometown mentioning how you use `mhost`. My work address is

```plain
     Lukas Pustina
     CenterDevice GmbH
     Rheinwerkallee 3
     53227 Bonn
     Germany
```
