_mhost() {
    local i cur prev opts cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}
    do
        case "${i}" in
            mhost)
                cmd="mhost"
                ;;
            
            discover)
                cmd+="__discover"
                ;;
            get-server-lists)
                cmd+="__get__server__lists"
                ;;
            lookup)
                cmd+="__lookup"
                ;;
            soa-check)
                cmd+="__soa__check"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        mhost)
            opts=" -p -q -v -h -V -S -s -f -o  --no-system-resolv-opt --no-system-nameservers --predefined --list-predefined --wait-multiple-responses --no-abort-on-error --no-abort-on-timeout --no-aborts --show-errors --quiet --no-color --ascii --help --version --resolv-conf --system-nameserver --nameserver --predefined-filter --nameservers-from-file --limit --max-concurrent-servers --max-concurrent-requests --retries --timeout --output --output-options   discover get-server-lists lookup soa-check"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --resolv-conf)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --system-nameserver)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                    -S)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --nameserver)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                    -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --predefined-filter)
                    COMPREPLY=($(compgen -W "udp tcp https tls" -- "${cur}"))
                    return 0
                    ;;
                --nameservers-from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                    -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-concurrent-servers)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-concurrent-requests)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retries)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -W "json summary" -- "${cur}"))
                    return 0
                    ;;
                    -o)
                    COMPREPLY=($(compgen -W "json summary" -- "${cur}"))
                    return 0
                    ;;
                --output-options)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        
        mhost__discover)
            opts=" -p -S -h -V -w  --show-partial-results --single-server-lookup --help --version --wordlist-from-file --rnd-names-number --rnd-names-len  <NAME> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --wordlist-from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                    -w)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rnd-names-number)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rnd-names-len)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        mhost__get__server__lists)
            opts=" -h -V -o  --help --version --output-file  <SERVER_LIST_SPEC>... "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --output-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                    -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        mhost__lookup)
            opts=" -S -w -h -V -t  --all --single-server-lookup --whois --help --version --record-type  <NAME | IP ADDR | CIDR BLOCK> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                --record-type)
                    COMPREPLY=($(compgen -W "A AAAA ANAME ANY CNAME MX NULL NS PTR SOA SRV TXT" -- "${cur}"))
                    return 0
                    ;;
                    -t)
                    COMPREPLY=($(compgen -W "A AAAA ANAME ANY CNAME MX NULL NS PTR SOA SRV TXT" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        mhost__soa__check)
            opts=" -p -h -V  --show-partial-results --help --version  <NAME> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

complete -F _mhost -o bashdefault -o default mhost
