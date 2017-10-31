# NAME

mhost - like `host` but uses multiple DNS servers massively parallel and compares results.


# SYNOPSIS

mhost [*options*] *DOMAIN_NAME*

mhost [*options*] *IP_ADDR*

mhost [*options*] --help

mhost [*options*] --version


# DESCRIPTION

mhost is a not so simple utility for performing DNS lookups. It is designed to use multiple DNS servers in parallel and combine their answers. In this way, it is easy to troubleshot DNS issues or even spot DNS server misconfigurations.

mhost comes with a predefined set of public DNS servers and can load DNS servers from the ungefiltert-surfen.de project which maintains large lists of public DNS servers per country - see *https://public-dns.info/* for further information. The default of mhost is to use the all local DNS servers listed in */etc/resolv.conf*.

mhost's output is colorized if supported by the terminal and can be controlled by several output modules. Currently, the default is a summary of all received responses. It also runs certain checks on the data, i.e., compares the serial numbers of SOA records. A detailed output shows the answers by each responding servers. These two output modules also support a human-friendly output in which case times and durations are shown as relative times as well as semantic output of certain resource records. Further, JSON output allows for easy automatic processing of the answers from scripts etc.

mhost uses UDP as transport protocol. Since UDP is an unreliable protocol, DNS queries and DNS responses may get lost. The likelihood for losses increases with the amount of servers used so it is not uncommon to get way less responses than DNS servers queried. Keep this in mind when using large amount of DNS server, for example, when using ungefiltert-surfen.de lists.

The project home page is *https://github.com/lukaspustina/mhost*.


# COMMON OPTIONS

*DOMAIN_NAME*
: Sets the domain name to lookup up.

    mhost preprocesses the domain name before constructing queries. For this purpose */etc/resolv.conf* is read for *ndots* and *domain* configurations. If *DOMAIN_NAME* contains less '.' then defined by *ndots* and a *domain* is set, *domain* is appended to the domain name. See also `-S`.

*IP_ADDR*
: Sets a dotted-decimal IPv4 address or a colon-delimited IPv6 address to lookup in which case a PTR query is performed.

-h
: Enabled human-readable output for output modules supporting this setting. Currently, their us human-readable support for SPF records as well as all times and durations as relative times. This examples show the output with and without human-readable output enabled:

        Received 2 (min 3, max 3 records) answers from 2 servers
        * SOA: origin NS sns.dns.icann.org., responsible party noc.dns.icann.org., serial 2017042799, refresh in 2 hours, retry in an hour, expire in 2 weeks, min in an hour (2)
        * TXT: SPF version: 1
               * Fail for all (2)
        * TXT: $Id: example.com 4415 2015-08-24 20:12:23Z davids $ (2)

        Received 2 (min 3, max 3 records) answers from 2 servers
        * SOA: origin NS sns.dns.icann.org., responsible party noc.dns.icann.org., serial 2017042799, refresh 7200 sec, retry 3600 sec, expire 1209600 sec, min 3600 sec (2)
        * TXT: v=spf1 -all (2)
        * TXT: $Id: example.com 4415 2015-08-24 20:12:23Z davids $ (2)

--help
: Prints help information

-o, --output *module_name* ...
: Selects the output module to use. Currently three modules are available: summary, details, json. This option can be used multiple times to select multiple modules. It is up to you make any sense of this.

    The summary output module is the default output module and summarizes all received results. The first line shows how many results from how many servers have been received as well as how the minimum and maximum amout of resource record from each server. Each resource record is printed with the amount of received answers in parenthesis. In this example, 20 answers have been received from 20 servers:

        Received 20 (min 2, max 2 records) answers from 20 servers
        * IPv4: 93.184.216.34 (20)
        * IPv6: 2606:2800:220:1:248:1893:25c8:1946 (20)

    The summary output module also prints alerts if certain checks on the collected records fail. Currently, the serial numbers of SOA records are compared and an alert is shown if they diverge like in this example where two different serial numbers have been reported by the queried servers:

        Received 20 (min 1, max 1 records) answers from 20 servers and found 1 alert.
        * SOA: origin NS sns.dns.icann.org., responsible party noc.dns.icann.org., serial 2017042801, refresh 7200 sec, retry 3600 sec, expire 1209600 sec, min 3600 sec (17)
        * SOA: origin NS sns.dns.icann.org., responsible party noc.dns.icann.org., serial 2017042802, refresh 7200 sec, retry 3600 sec, expire 1209600 sec, min 3600 sec (3)
        Alert
        * SOA serial numbers diverge: {2017042802: 3, 2017042801: 17}

    The details output module presents the received resource records for each server together with the corresponding TTL. In this example, the answers of two servers are printed.

        DNS server 8.8.8.8 responded with
        * IPv4: 93.184.216.34 [expires in 3108 sec]
        * IPv6: 2606:2800:220:1:248:1893:25c8:1946 [expires in 3194 sec]
        DNS server 8.8.4.4 responded with
        * IPv4: 93.184.216.34 [expires in 4836 sec]
        * IPv6: 2606:2800:220:1:248:1893:25c8:1946 [expires in 16874 sec]

    The json output module is similar to the details module but prints the results list as a JSON array.

-p
: Adds predefined public DNS servers to list of DNS servers to query. See *https://github.com/lukaspustina/mhost/blob/master/src/defaults.rs*.

-s, --server *ip_address*
: Adds DNS servers to list of DNS servers to query. This option can be used multiple times to select multiple servers.

-t, --type *record_type*
: Select resource record types to query.

    Supported resource record types are a, aaaa, any, cname, dnskey, mx, ns, opt, ptr, soa, srv, and txt. Default is a, aaaa, and mx.

-u *country_id*
: Retrieves DNS servers from ungefiltert-surfen.de and adds them to list of DNS servers to query. This option can be used multiple times to retrieve multiple lists.

    *country_id* is usually a country top-level domain. For example for Germany and the Czech Republic:

        -u de,cz


# LESS COMMON OPTIONS

-d
: Sets debug level. Can be used to up to three times to increase debug level.

--hide-headers
: Hides output headers.

-l
: Limits the amount of servers to query. The default is 100.

-L
: Ignores local search domains from */etc/resolv.conf*.

-S
: Ignore local search domains from */etc/resolv.conf*.

--timeout *timeout*
: Sets timeout for server responses in sec. The default is 5 sec.

--show-nxdomain
: Shows NXDOMAIN responses that servers send if no records can be found for a domain name.

--show-unsupported
: Show unsupported resource records. In case an "any" request is performed and unsupported resource records received, these records will be shown in an unparsed fashion.

-v
: Sets level of verbosity. Can be used to up to three times to increase verbosity level.

-V, --version
: Prints version information.


# SHELL COMPLETION

--completions *shell*
: Generates shell completions for supported shells which are currently bash, fish, and zsh.


# FILES
 */etc/resolv.conf*


# SEE ALSO
host(1), dig(1), resolver(5)


# COPYRIGHT AND LICENSE

Copyright (c) 2017 Lukas Pustina. Licensed under the MIT License. See *https://github.com/lukaspustina/mhost/blob/master/LICENSE* for details.

