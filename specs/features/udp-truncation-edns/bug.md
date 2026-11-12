# Bug: udp-truncation-edns

Written by `adlc feature start --bug`. The first four sections are yours; diagnose fills the last three.

## Symptom

Source: GitHub issue #797. A lookup whose answer does not fit a plain 512-byte UDP response fails over the UDP transport: `mhost -v --show-errors lookup -t TXT microsoft.com.` against the system resolver (`udp:127.0.0.1:53`) reports `resolver error: response was truncated; TCP already tried or no other transport available` and 0 responses. The same lookup over TCP (`-S -s tcp:127.0.0.1`) succeeds. The reporter's diagnosis: mhost does not send EDNS, so the server caps UDP answers at 512 bytes and sets TC.

## Expected

A UDP lookup of a large RRset (e.g. TXT microsoft.com.) returns the records: mhost advertises an EDNS UDP payload size so the answer fits one UDP response, and a response that is still truncated is retried over TCP instead of ending in an error. Forcing TCP for every query is not acceptable, since public nameservers rate-limit TCP.

## Reproduction

mhost -v --show-errors lookup -t TXT microsoft.com.          (system resolver, UDP: fails)
mhost -v --show-errors -S -s tcp:127.0.0.1 lookup -t TXT microsoft.com.   (TCP: works)

## Environment

mhost 0.12.1 on RHEL10; system resolver from /etc/resolv.conf is a local stub at 127.0.0.1:53; record set: TXT microsoft.com. (well above 512 bytes).

## Loop

Run from the repository root after `cargo build`, against 8.8.8.8 instead of the reporter's local
stub (same code path: a `udp:` nameserver; the system resolver from resolv.conf becomes one too):

```
$ ./target/debug/mhost --no-color --show-errors -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.
```

Run 1:

```
▸ Received 0 responses with 0 RR [], 0 Nx, 1 Err [0 TO, 0 QR, 0 SF, 1 O] in (min -, max -) ms from 0 servers within 4183 ms of total run time.
▸ Error counts
 ∙ resolver error: response was truncated; TCP already tried or no other transport available (1 times)
❖ Finished.
```

Run 2:

```
▸ Received 0 responses with 0 RR [], 0 Nx, 1 Err [0 TO, 0 QR, 0 SF, 1 O] in (min -, max -) ms from 0 servers within 9 ms of total run time.
▸ Error counts
 ∙ resolver error: response was truncated; TCP already tried or no other transport available (1 times)
❖ Finished.
```

Red on the reporter's exact error text both times. The process exits 0 either way, so the pass
condition is the output, not the exit code. Needs network (UDP and TCP to 8.8.8.8:53); it does not
run inside the sandbox.

## Hypotheses

1. **EDNS is not sent** — `ResolverOpts::to_proto` (`src/resolver/mod.rs`) leaves hickory's `edns0` off, so the server caps the answer at 512 bytes. Refuted if hickory 0.26 defaults `edns0` to on and `lookup` uses it. **refuted** (read): hickory-resolver 0.26.3 `config.rs:654` `edns0: true`, `edns_payload_len` defaults to `DEFAULT_MAX_PAYLOAD_LEN = 1232` (hickory-proto `op/edns.rs:292`), and `Resolver::lookup` passes `self.request_options()`, which sets `use_edns = options.edns0` (`resolver.rs:160`, `:353`). mhost's `single_lookup` calls that `lookup` (`src/resolver/lookup.rs:667`). EDNS with 1232 bytes is already sent.
2. **A larger EDNS payload would make the answer fit** — raising `edns_payload_len` in `ResolverOpts::to_proto` would avoid the truncation. Refuted if the answer is larger than any sane payload or the server caps UDP regardless. **refuted** (changed input): `dig +ignore +norec +bufsize=4096 @8.8.8.8 TXT microsoft.com.` returns `flags: qr tc ra`, `ANSWER: 0`, and the server's OPT says `udp: 512`; the full answer over TCP is `MSG SIZE rcvd: 4782`. No UDP payload size fixes this; the answer needs TCP.
3. **mhost turns a usable response into an error** — the error mapping in `IntoLookup` (`src/resolver/lookup.rs`) drops a truncated answer that hickory delivered. Refuted if the error is produced inside hickory. **refuted** (read): the text is hickory-net 0.26.3 `NetError::Truncated` (`error.rs:161`), raised in hickory-resolver `name_server_pool.rs:384-386` when a truncated response arrives with `policy.disable_udp` already set; mhost only reports it.
4. **A `udp:` nameserver has no TCP connection, so hickory's TC→TCP fallback has nowhere to go** — `NameServerConfig::to_proto` (`src/nameserver/mod.rs:334`) builds one `ConnectionConfig` with `ProtocolConfig::Udp` only. On TC, hickory sets `disable_udp` and retries the same server (`name_server_pool.rs:388-392`), finds no non-UDP connection, and the second pass ends in `Truncated`. Refuted if adding a TCP connection to the UDP server's config leaves the loop red. **held** (probe): with `to_proto` returning `vec![udp, tcp]` (same port) for `NameServerConfig::Udp`, the loop printed `Received 1 responses with 62 RR [62 TXT], 0 Nx, 0 Err` and `✓ No errors occurred.` on two runs; the probe was then removed.

## Root cause

A `udp:` nameserver is handed to hickory with a UDP connection only. hickory-resolver 0.26.3
answers a truncated UDP response by retrying the same server with UDP disabled; with no TCP
connection configured that retry has no transport and fails with `NetError::Truncated`
("response was truncated; TCP already tried or no other transport available"). EDNS is already
sent (1232 bytes, hickory's default) and is not the fix: 8.8.8.8 caps UDP at 512 bytes and the
TXT microsoft.com. answer is 4782 bytes, so the answer only ever arrives over TCP. The reporter's
system resolver takes the same path, since resolv.conf nameservers become `udp:` configs unless
`use-vc` is set.

The UDP config gets a single UDP connection:

```quote src/nameserver/mod.rs:334
            NameServerConfig::Udp { .. } => ConnectionConfig::new(ProtocolConfig::Udp),
```

and is passed to hickory with only that connection:

```quote src/nameserver/mod.rs:344
        hickory_resolver::config::NameServerConfig::new(config.ip_addr(), true, vec![connection])
```

System nameservers take the same path:

```quote src/nameserver/mod.rs:319
                ScopedIp::V4(ipv4) => NameServerConfig::udp_with_name((ipv4, 53), "System".to_string()),
```

The lookup reaches hickory (0.26.3) here:

```quote src/resolver/lookup.rs:667
        .lookup(q.name.as_proto().clone(), q.record_type.to_proto())
```

Evidence: hypothesis 4's probe turned the loop green (62 TXT records, 0 errors) twice.
hickory's own `NameServerConfig::udp_and_tcp` builds exactly this pair, UDP first, TCP for
fallback.
