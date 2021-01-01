# 2. Output Guards in Module Output

Date: 2020-12-14

## Status

Superceded by [4. Output Guards in Module Output](0004-output-guards-in-module-output.md)

## Context

App modules print their output using the `Console` module. Guard are used to control whether a specific output is printed in `quiet`, `partial-output`, `show-error` etc. mode. There are two ways to implement these guards: 1. hidden from the call site by integrating the guard into the specific output method or 2. at call site around the specific output method.

## Decision

All guards controlling whether a particular output is printed or not will be _in_ the app modules _at_ call site. This gives finer control if an app module deviates from the standard path of printing.

## Consequences

This decision leads to redundant `if`-blocks around the printing.
