# 1. Record architecture decisions

Date: 2020-12-10

## Status

Accepted

## Context

I need to record the architectural decisions made on this project.

I've been working on this project on and off for about three years, rewriting the code three times. Due to the long pauses, changing requirements, new ideas, and constant advances in Rust, I've made a lot of decision decisions that are not clear to me just by looking at the code structure or the code itself. This leads to cognitive extra-load, poor implementations, and especially additional friction when picking up the project again.

I especially have trouble remembering decisions regarding how to work around Rust short-comings like no `async` in traits or coding patterns I rarely use.

## Decision

I will persist my thoughts and motivation for decisions using Architecture Decision Records (ADR), as [described by Michael Nygard](http://thinkrelevance.com/blog/2011/11/15/documenting-architecture-decisions).

## Consequences

Going back and understanding architecture, structure, code, and especially "won't fixes" will be easier to remember and understand.

ARDs have an additional impact on productivity and will increase the booking in this project. I also do not know how this will relate to inline comments and Rust Docs.

See Michael Nygard's article, linked above. For a lightweight ADR toolset, see Nat Pryce's [adr-tools](https://github.com/npryce/adr-tools).
