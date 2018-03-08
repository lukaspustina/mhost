# mhost

mhost is a not so simple utility for performing DNS lookups. It is designed to use multiple DNS servers in parallel and combine their answers.  In this way, it is easy to troubleshot DNS issues or even spot DNS server misconfigurations.

mhost comes with a predefined set of public DNS servers and can load DNS servers from the [ungefiltert-surfen.de](https://public-dns.info/) project, which maintains large lists of public DNS servers per country. By default mhost uses all local DNS servers listed in */etc/resolv.conf*.

mhost's output is colorized if supported by the terminal and can be controlled by several output modules. Currently, the default is a summary of all received responses. It also runs certain checks on the data, e.g. it compares the serial numbers of SOA records. A detailed output shows the answers from all responding servers. These two output modules also support a human-friendly output with times and durations shown as relative times, as well as semantic output of certain resource records. Further, JSON output allows for easy automatic processing of the answers from scripts etc.

mhost uses UDP as the transport protocol. Since UDP is an unreliable protocol, DNS queries and DNS responses may get lost. The likelihood for losses increases with the number of servers used, so it is not uncommon to get way less responses than DNS servers queried. Keep this in mind when querying many DNS servers, for example, when using ungefiltert-surfen.de lists.

For details on mhost's functionality and how to use it, please see the [man](docs/mhost.1.md) page.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Changelog](#changelog)
- [Why should I use mhost?](#why-should-i-use-mhost)
- [Use Cases](#use-cases)
  - [Use Operating System's default Resolver and Google's public DNS servers](#use-operating-systems-default-resolver-and-googles-public-dns-servers)
  - [Use 100 DNS German Servers from ungefiltert-surfen](#use-100-dns-german-servers-from-ungefiltert-surfen)
  - [Output JSON for post-processing](#output-json-for-post-processing)
- [Installation](#installation)
  - [Ubuntu [x86_64 and Raspberry Pi]](#ubuntu-x86_64-and-raspberry-pi)
  - [Linux Binaries [x86_64 and Raspberry Pi]](#linux-binaries-x86_64-and-raspberry-pi)
  - [Windows Binaries [x86_64 and i686]](#windows-binaries-x86_64-and-i686)
  - [macOS](#macos)
  - [Sources](#sources)
- [Postcardware](#postcardware)
- [Thanks](#thanks)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Changelog

Please see the [CHANGELOG](CHANGELOG.md) for a release history.


## Why should I use mhost?

* JSON output

## Use Cases

### Use Operating System's Default Resolver and Google's public DNS servers

`mhost -s 8.8.8.8 -s 8.8.4.4 github.com`

### Use 100 DNS German Servers from [ungefiltert-surfen](https://www.ungefiltert-surfen.de)

`mhost -u de github.com`

### Output JSON for post-processing

`mhost -u de -o json github.com`


## Installation

### Ubuntu [x86_64 and Raspberry Pi]

Please add my [PackageCloud](https://packagecloud.io/lukaspustina/opensource) open source repository and install `mhost` via apt.

```bash
curl -s https://packagecloud.io/install/repositories/lukaspustina/opensource/script.deb.sh | sudo bash
sudo apt-get install mhost
```

### Linux Binaries [x86_64 and Raspberry Pi]

There are binaries available at the GitHub [release page](https://github.com/lukaspustina/mhost/releases). The binaries get compiled on Ubuntu.

### Windows Binaries [x86_64 and i686]

There are binaries available at the GitHub [release page](https://github.com/lukaspustina/mhost/releases).

### macOS

Please use [Homebrew](https://brew.sh) to install `mhost` on your system.

```bash
brew install lukaspustina/os/mhost
```

### Sources

Please install Rust via [rustup](https://www.rustup.rs) and then run

```bash
git clone https://github.com/lukaspustina/mhost
cd mhost
cargo build
```

  
## Postcardware

You're free to use `mhost`. If you find it useful, I would highly appreciate you sending me a postcard from your hometown mentioning how you use `mhost`. My work address is

```
Lukas Pustina
CenterDevice GmbH
Rheinwerkallee 3
53227 Bonn
Germany
```

## Thanks

Thanks to [Benjamin Fry](https://github.com/bluejekyll) for his literally wonderful [TRust-DNS](http://trust-dns.org) server and the corresponding client library which does all the heavy lifting of `mhost`.

