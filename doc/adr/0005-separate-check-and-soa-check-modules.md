# 5. Separate check and SOA check modules

Date: 2021-01-03

## Status

Accepted

## Context

There are currently two modules that check and lint responses: 1. `soa-check` and 2. `check`. They both perform similar tasks and could be merged, or not.

## Decision

These two modules will be kept separate, because follow different approaches. `soo-check` checks the responses of authoritative name servers. For this purpose it determines what the authoritative name servers are and asks these to provide their SOA records. `check` lints the responses given my the selected name servers. It does not strive to get answers from authoritative name servers. In this way, it gives a view of a zone, by inspecting the answers from arbitrary name servers.

## Consequences

This is going to lead to confusion and maybe even double implementation of specific tasks.
