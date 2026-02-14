# 4. Output Guards in Module Output

Date: 2021-01-02

## Status

Accepted

Supercedes [2. Output Guards in Module Output](0002-output-guards-in-module-output.md)

## Context

App modules print their output using the `Console` module. Guard are used to control whether a specific output is printed in `quiet`, `partial-output`, `show-error` etc. mode. There are two ways to implement these guards: 1. hidden from the call site by integrating the guard into the specific output method  or 2. at call site around the specific output method.

## Decision

Guards are part of the `Console` printing methods. If necessary, `Console` offers means to implement guards and printing at call site, too.

## Consequences

This makes it easier to use the output in the modules without re-thinking the individual guards.
