# 6. Prefer CLI parameters over etc-resolv.conf

Date: 2021-01-06

## Status

Accepted

## Context

Usually, on Unix compatible system, `/etc/resolv.conf` used to control DNS lookups. For example, search domains, nameservers, lookup timeout etc. used to be set in this file. Nowadays, this file is generated automatically by various daemons and is thus not really stable anymore. Furthermore, the meaning, relevance, and default values vary a lot between different OSs especially macOS. This makes is very difficult to use the configuration for `mhost` while also giving the user a consistent experience.

## Decision

`mhost` will use `/etc/resolv.conf` to determine the system's nameservers and their configuration, i.e., number of retries, ndots, timeout. This configuration will be used for system lookups only. For all other nameservers used to make lookups, `mhost` will use the configuration provided by the CLI parameters or their default values, respectively. The configuration for search domains will be determined by the local host's FQDN or by a CLI parameter.

There will be a special CLI parameter that enforces to load and use the configuration for number of retries, ndots and timeout from `/etc/resolv.conf` override the corresponding CLI parameters.

## Consequences

This should make the configuration as predictable and uniform across all OSs as possible while a little bit surprising for the user who might expect all values in `/etc/resolv.conf` to be respected by default.
