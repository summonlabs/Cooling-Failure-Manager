# Contributing to Cooling Failure Manager

Thank you for your interest in contributing to Cooling Failure Manager. This
document describes the contribution terms and the engineering expectations for
this repository.

## License

By contributing to this project, you agree that your contributions are licensed
under the **Apache License, Version 2.0**. See the LICENSE file for the full
license text and the NOTICE file for attribution and license notices. There is
**no separate Contributor License Agreement (CLA)** requirement: you retain
ownership of your contributions and grant the project a license to use them
under the terms of the Apache License 2.0.

## License headers

Every source file carries:

    // SPDX-License-Identifier: Apache-2.0
    // Copyright 2026 Summon Software Labs.

## Coding standards

- C++20 and CMake only. No third-party dependencies, no network access during
  configure, build or test.
- Build cleanly with /W4 /WX on MSVC and -Wall -Wextra -Wpedantic -Werror
  elsewhere. Fix warning causes rather than suppressing warnings.
- Public identities, generations, epochs, incarnations, sequences, ordinals and
  store generations are distinct strong types. Do not add implicit conversions
  between them, and never derive one from another.
- All external input is untrusted. Validate before allocating, use checked
  arithmetic for externally influenced sizes and counters, and reject malformed
  input instead of normalizing it.
- **Missing evidence is not health.** Zero, unknown, indeterminate, unsupported
  and absent are different answers and must stay different. There is no code
  path anywhere in this repository that substitutes a value for a reading that
  does not exist.
- **Eligibility, solicitation, acknowledgement, observed effect and verified
  effect are five separate facts.** Never let one stand in for another.
- Where iteration order is public or serialized, it is documented, total and
  tested. Do not rely on hash-container iteration order for anything observable.
- A value read out of a Result must be held in a named variable before it is
  used elsewhere; do not take a reference into a temporary.

## Architecture boundaries

This repository owns **cooling-failure semantics**:

- cooling failure classification for the classes in enums.hpp;
- the affected scope set, derived from this component's own projection of the
  cooling graph;
- response-plan state: eligibility, solicitation, acknowledgement, observed
  effect and verified effect, kept apart;
- protective restrictions and their bounded release;
- recovery gates and the permitted / deferred / blocked verdict;
- generation-bound authority and fencing, and durable attempt and evidence
  history.

It explicitly does **not** own:

- cooling topology, capacity arithmetic, thermal-zone state, airflow or liquid
  cooling actuation;
- the generic incident lifecycle or generic recovery;
- workload scheduling or placement;
- thermal-safety policy, which belongs to Thermal Emergency Manager;
- cooling source selection, which belongs to Cooling Failover.

A change that makes this repository decide any of those is out of scope and will
be refused regardless of how convenient it is.

## Evidence discipline

Every decision this component publishes must be reproducible from its inputs
alone. The test suite enforces this: an evaluation reads no clock, no
environment, no file and no global state, and the canonical encoding of two
states that differ only in insertion order is byte-identical.

New behaviour needs:

- an exact ErrorCode for every documented rejection;
- a deterministic unit or integration test;
- where the behaviour is a rule, a documented statement of the rule at the code
  that implements it and a test that pins it;
- where the behaviour is a bound, a test at the bound and one step past it.

Randomized tests must derive their seed from the test name, print their
parameters on failure, and check their invariant after every mutation.

## Durability

The durable store's commit point is one atomic directory-entry replacement, and
its crash behaviour is documented in docs/FORMATS.md. A change to the store must
keep the protocol's ordering and must extend the crash-injection test suite with
the new boundary. A claim of durability that was not established is a defect,
not a shortcut.

## Reporting a problem

Open an issue with:

- the exact command and the exact output;
- the smallest input that reproduces it;
- whether it is a wrong answer, a missing refusal, a crash or a documentation
  mismatch.

A report that says the classification is wrong without the evidence inputs and
the expected class is not actionable, because classification is a pure function
of those inputs and can always be reproduced.
