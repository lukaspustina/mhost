# 3. Separate CLI Tests for CI and no-CI

Date: 2020-12-23

## Status

Accepted

## Context

Currently, GitHub Actions are used for CI. Unfortunately, GitHub Actions [do not support IPv6](https://github.com/actions/virtual-environments/issues/668#issuecomment-624080758). Therefore, tests requiring or at least relying on IPv6 fail in GitHub CI.

## Decision

In order to circumvent tests either failing tests in GitHub CI or reducing tests to GitHub Actions network capabilities only, integration tests are split into to sets: One set, the standard set, that runs on GitHub Actions and another set, the local only set, that runs tests using IPv6. Tests of the second test will be configured as `#[ignore]` preventing them to execute in GitHub CI runs. These tests can be run locally using the Makefile target `test`.

## Consequences

The problematic consequence is that GitHub CI does not guarantee to run all available tests anymore. On the other hand, we still _do_ have these tests and the Makefile target automatically includes them during local test execution.

