complete -c mhost -n "__fish_use_subcommand" -l resolv-conf -d 'Uses alternative resolv.conf file'
complete -c mhost -n "__fish_use_subcommand" -l ndots -d 'Sets number of dots to qualify domain name as FQDN'
complete -c mhost -n "__fish_use_subcommand" -s S -l system-nameserver -d 'Adds system nameserver for system lookups; only IP addresses allowed'
complete -c mhost -n "__fish_use_subcommand" -s s -l nameserver -d 'Adds nameserver for lookups'
complete -c mhost -n "__fish_use_subcommand" -l predefined-filter -d 'Filters predefined nameservers by protocol' -r -f -a "udp tcp https tls"
complete -c mhost -n "__fish_use_subcommand" -s f -l nameservers-from-file -d 'Adds nameserver for lookups from file'
complete -c mhost -n "__fish_use_subcommand" -l limit -d 'Sets max. number of nameservers to query'
complete -c mhost -n "__fish_use_subcommand" -l max-concurrent-servers -d 'Sets max. concurrent nameservers'
complete -c mhost -n "__fish_use_subcommand" -l max-concurrent-requests -d 'Sets max. concurrent requests per nameserver'
complete -c mhost -n "__fish_use_subcommand" -l retries -d 'Sets number of retries if first lookup to nameserver fails'
complete -c mhost -n "__fish_use_subcommand" -l timeout -d 'Sets timeout in seconds for responses'
complete -c mhost -n "__fish_use_subcommand" -s o -l output -d 'Sets the output format for result presentation' -r -f -a "json summary"
complete -c mhost -n "__fish_use_subcommand" -l output-options -d 'Sets output options'
complete -c mhost -n "__fish_use_subcommand" -l no-system-resolv-opt -d 'Ignores options set in /etc/resolv.conf'
complete -c mhost -n "__fish_use_subcommand" -l no-system-nameservers -d 'Ignores nameservers from /etc/resolv.conf'
complete -c mhost -n "__fish_use_subcommand" -s p -l predefined -d 'Adds predefined nameservers for lookups'
complete -c mhost -n "__fish_use_subcommand" -l list-predefined -d 'Lists all predefined nameservers'
complete -c mhost -n "__fish_use_subcommand" -l wait-multiple-responses -d 'Waits until timeout for additional responses from nameservers'
complete -c mhost -n "__fish_use_subcommand" -l no-abort-on-error -d 'Sets do-not-ignore errors from nameservers'
complete -c mhost -n "__fish_use_subcommand" -l no-abort-on-timeout -d 'Sets do-not-ignore timeouts from nameservers'
complete -c mhost -n "__fish_use_subcommand" -l no-aborts -d 'Sets do-not-ignore errors and timeouts from nameservers'
complete -c mhost -n "__fish_use_subcommand" -l show-errors -d 'Shows error counts'
complete -c mhost -n "__fish_use_subcommand" -s q -l quiet -d 'Does not print anything but results'
complete -c mhost -n "__fish_use_subcommand" -l no-color -d 'Disables colorful output'
complete -c mhost -n "__fish_use_subcommand" -l ascii -d 'Uses only ASCII compatible characters for output'
complete -c mhost -n "__fish_use_subcommand" -s v -d 'Sets the level of verbosity'
complete -c mhost -n "__fish_use_subcommand" -l debug -d 'Uses debug formatting for logging -- much more verbose'
complete -c mhost -n "__fish_use_subcommand" -s h -l help -d 'Prints help information'
complete -c mhost -n "__fish_use_subcommand" -s V -l version -d 'Prints version information'
complete -c mhost -n "__fish_use_subcommand" -f -a "check" -d 'Checks all available records for known misconfigurations or mistakes'
complete -c mhost -n "__fish_use_subcommand" -f -a "discover" -d 'Discovers records of a domain using multiple heuristics'
complete -c mhost -n "__fish_use_subcommand" -f -a "get-server-lists" -d 'Downloads known lists of name servers'
complete -c mhost -n "__fish_use_subcommand" -f -a "lookup" -d 'Looks up a name, IP address or CIDR block'
complete -c mhost -n "__fish_use_subcommand" -f -a "soa-check" -d 'Checks SOA records of authoritative name servers for deviations'
complete -c mhost -n "__fish_seen_subcommand_from check" -s p -l show-partial-results -d 'Shows results after each check step'
complete -c mhost -n "__fish_seen_subcommand_from check" -l no-spf -d 'Does not run SPF check'
complete -c mhost -n "__fish_seen_subcommand_from check" -l no-record-type-lint -d 'Does not run record type lints'
complete -c mhost -n "__fish_seen_subcommand_from check" -s h -l help -d 'Prints help information'
complete -c mhost -n "__fish_seen_subcommand_from check" -s V -l version -d 'Prints version information'
complete -c mhost -n "__fish_seen_subcommand_from discover" -s w -l wordlist-from-file -d 'Uses wordlist from file'
complete -c mhost -n "__fish_seen_subcommand_from discover" -l rnd-names-number -d 'Sets number of random domain names to generate for wildcard resolution check'
complete -c mhost -n "__fish_seen_subcommand_from discover" -l rnd-names-len -d 'Sets length of random domain names to generate for wildcard resolution check'
complete -c mhost -n "__fish_seen_subcommand_from discover" -s p -l show-partial-results -d 'Shows results after each lookup step'
complete -c mhost -n "__fish_seen_subcommand_from discover" -s S -l single-server-lookup -d 'Switches into single server lookup mode: every query will be send just one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.'
complete -c mhost -n "__fish_seen_subcommand_from discover" -s h -l help -d 'Prints help information'
complete -c mhost -n "__fish_seen_subcommand_from discover" -s V -l version -d 'Prints version information'
complete -c mhost -n "__fish_seen_subcommand_from get-server-lists" -s o -l output-file -d 'Sets path to output file'
complete -c mhost -n "__fish_seen_subcommand_from get-server-lists" -s h -l help -d 'Prints help information'
complete -c mhost -n "__fish_seen_subcommand_from get-server-lists" -s V -l version -d 'Prints version information'
complete -c mhost -n "__fish_seen_subcommand_from lookup" -s t -l record-type -d 'Sets record type to lookup, will be ignored in case of IP address lookup' -r -f -a "A AAAA ANAME ANY CNAME MX NULL NS PTR SOA SRV TXT"
complete -c mhost -n "__fish_seen_subcommand_from lookup" -l all -d 'Enables lookups for all record types'
complete -c mhost -n "__fish_seen_subcommand_from lookup" -s S -l single-server-lookup -d 'Switches into single server lookup mode: every query will be send just one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.'
complete -c mhost -n "__fish_seen_subcommand_from lookup" -s w -l whois -d 'Retrieves Whois information about A, AAAA, and PTR records.'
complete -c mhost -n "__fish_seen_subcommand_from lookup" -s h -l help -d 'Prints help information'
complete -c mhost -n "__fish_seen_subcommand_from lookup" -s V -l version -d 'Prints version information'
complete -c mhost -n "__fish_seen_subcommand_from soa-check" -s p -l show-partial-results -d 'Shows results after each lookup step'
complete -c mhost -n "__fish_seen_subcommand_from soa-check" -s h -l help -d 'Prints help information'
complete -c mhost -n "__fish_seen_subcommand_from soa-check" -s V -l version -d 'Prints version information'
