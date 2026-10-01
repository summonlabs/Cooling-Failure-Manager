# Cooling Failure Manager - internal formats

Copyright 2026 Summon Software Labs. SPDX-License-Identifier: Apache-2.0

This file is an implementation contract for the two on-disk/in-memory formats.
It is not a public API document.

General rules for both formats:

* ASCII only. Every byte outside printable ASCII appears only escaped.
* Line separator is a single LF (0x0A). CR is rejected, never tolerated.
* Field separator is a single TAB (0x09).
* Empty lines are rejected unless a rule explicitly allows one.
* Integers are canonical decimal: no leading '+', no leading zeroes, no
  whitespace, "-0" rejected. Bounds are checked on decode.
* Booleans are the single characters "0" and "1".
* Text fields never contain a raw TAB, LF, CR or NUL: they are escaped with the
  escape_text() codec, which is always quoted.
* Digests are 64 lowercase hex characters.
* Identifiers use the canonical StrongId grammar
  (1..128 bytes, first/last ASCII alphanumeric, interior [A-Za-z0-9._:-]).
* The decoder is strict and total: every rejection returns an error, no default,
  no repair, no partial result.

---

## 1. Canonical state encoding

Format name: `dccp-cooling-failure-state`
Format version: `1`

Structure:

    dccp-cooling-failure-state<TAB>1<TAB><fields...>
    <records...>
    end<TAB><record_count><TAB><sha256-hex-of-every-preceding-byte-including-the-preceding-LF>

The digest covers every byte from offset 0 up to and including the LF that
terminates the last record line. The `end` line itself is not covered.

Two different digests are computed over a state, and they are not
interchangeable:

* the **end-line digest** is the value written in the `end` line. It covers the
  body only, as stated above, and its purpose is to detect a damaged or
  truncated record stream at the point of decoding.
* the **state digest** (`state_digest()`) is SHA-256 over the *whole* canonical
  encoding, including the `end` line. It is the identity of the state as a
  value, and it is the digest the store writes into a generation file header and
  compares on every read.

A reader that has decoded a state and wants the value the header declares must
recompute the state digest by re-encoding, not by reusing the end-line digest
from the text it read.

The header line is:

    dccp-cooling-failure-state<TAB>1<TAB>generation=<u64><TAB>parent=<u64><TAB>clock=<i64>

Records are emitted in this fixed order. Within each group, records are emitted
in the canonical order produced by canonicalize().

    state<TAB>bindings=<n><TAB>scopes=<n><TAB>failures=<n><TAB>plans=<n><TAB>evidence=<n><TAB>decisions=<n><TAB>unresolved=<n>
    binding<TAB>role=<token><TAB>owner=<text><TAB>identity=<text><TAB>generation=<u64>
    scope<TAB>id=<id><TAB>kind=<token><TAB>name=<text><TAB>bindings=<n><TAB>deps=<n><TAB>strict=<n><TAB>reqs=<n><TAB>dwell=<i64><TAB>hysteresis=<i64><TAB>service_floor=<token><TAB>max_supply_temp=<i64>:<unit><TAB>min_thermal_margin=<i64>:<unit><TAB>min_flow=<i64>:<unit><TAB>min_dp=<i64>:<unit><TAB>demand=<i64>:<unit>
    scopeb<TAB>scope=<id><TAB>role=<token><TAB>owner=<text><TAB>identity=<text><TAB>generation=<u64>
    scopeclass<TAB>scope=<id><TAB>class=<token>
    scopereq<TAB>scope=<id><TAB>channel=<token><TAB>window=<i64>
    scopedep<TAB>scope=<id><TAB>upstream=<id><TAB>kind=<token><TAB>share=<i64>
    failure<TAB>id=<id><TAB>scope=<id><TAB>class=<token><TAB>confirmation=<token><TAB>severity=<token><TAB>urgency=<token><TAB>tti=<token><TAB>at=<i64><TAB>basis=<n><TAB>shared_source=<id-or-empty><TAB>rationale=<text>
    failurebasis<TAB>failure=<id><TAB>observation=<id><TAB>ordinal=<u32>
    plan<TAB>id=<id><TAB>scope=<id><TAB>lifecycle=<token><TAB>updated_at=<i64><TAB>failures=<n><TAB>eligible=<n><TAB>restrictions=<n><TAB>attempts=<n><TAB>solicited=<token><TAB>has_solicited=<bool><TAB>explanation=<text>
    planfailure<TAB>plan=<id><TAB>failure=<id>
    planeligible<TAB>plan=<id><TAB>action=<token><TAB>effect_class=<token><TAB>safety_critical=<bool><TAB>rank=<i32><TAB>rule_id=<text>
    restriction<TAB>id=<id><TAB>scope=<id><TAB>plan=<id><TAB>kind=<token><TAB>ceiling=<i64>:<unit><TAB>released_by=<n>
    restrictionfailure<TAB>restriction=<id><TAB>failure=<id>
    attempt<TAB>id=<id><TAB>solicitation=<id><TAB>ordinal=<u32><TAB>action=<token><TAB>effect_class=<token><TAB>state=<token><TAB>addressee=<text><TAB>solicited_at=<i64><TAB>acknowledged_at=<i64-or--1><TAB>updated_at=<i64><TAB>effect_observation=<id-or-empty><TAB>verdict=<text><TAB>adopted=<bool>
    evidence<TAB>observation=<id><TAB>scope=<id><TAB>channel=<token><TAB>status=<token><TAB>freshness=<token><TAB>availability=<token><TAB>quality=<token><TAB>age=<i64><TAB>detail=<text>
    decision<TAB>scope=<id><TAB>at=<i64><TAB>severity=<token><TAB>urgency=<token><TAB>tti=<token><TAB>binding=<token><TAB>recovery=<token><TAB>plan=<id-or-empty><TAB>confirmed=<n><TAB>suspected=<n><TAB>contradicted=<n><TAB>unknown=<n><TAB>failures=<n><TAB>shared=<n><TAB>restrictions=<n><TAB>gaps=<n><TAB>explanation=<n>
    decisionclass<TAB>scope=<id><TAB>bucket=<token><TAB>class=<token><TAB>ordinal=<u32>
    decisionfailure<TAB>scope=<id><TAB>failure=<id><TAB>ordinal=<u32>
    decisionshared<TAB>scope=<id><TAB>source=<id><TAB>ordinal=<u32>
    decisionrestriction<TAB>scope=<id><TAB>restriction=<id><TAB>ordinal=<u32>
    decisiongap<TAB>scope=<id><TAB>channel=<token><TAB>ordinal=<u32>
    decisiontext<TAB>scope=<id><TAB>ordinal=<u32><TAB>text=<text>
    unresolved<TAB>attempt=<id><TAB>ordinal=<u32>

`<text>` is the escape_text() rendering, which is always a quoted
string; unescape_text() restores the exact bytes.

`<i64-or--1>` uses -1 for an absent clock. A clock is never negative
otherwise.

The decoder verifies, in order:

1. header format name and version;
2. the declared counts against the body it actually read;
3. the `end` digest over every preceding byte;
4. strict field shapes for every record;
5. referential integrity and canonical ordering through validate_structure();
6. the canonical fixed point: re-encoding the decoded state must reproduce the
   identical bytes.

A failure at any step returns an error and no state.

---

## 2. Durable store

Layout of the store root:

    lock                  OS-level exclusive writer lock file (advisory text)
    floor                 durable monotone generation floor
    manifest              authoritative head record (the commit point)
    manifest.prev         previous committed head record
    generations/          immutable generation files
    idem/                 accepted-attempt records written by release 1.0.0
    staging/              transient staging area; empty between publications

Generation file name: `g<20-digit-zero-padded-generation>.dat`

Idempotency file name: `m<sha256-hex-of-(mutation-id + tab + ordinal)>.dat`

Since release 1.0.1 the accepted-attempt record of a publication is carried by
the retained manifest entry that commits it, and `idem/` holds nothing on a store
this release created. The directory is still read, so a store written by 1.0.0
keeps the replay guarantee its existing records describe, and files that
disagree with the committed authority are reported by verification as
`replay.inconsistent`.

### 2.1 floor

    dccp-cooling-failure-floor<TAB>1<TAB>floor=<u64><TAB>count=<u64><TAB><sha256-hex>

The digest covers every byte up to and including the TAB before it.

### 2.2 manifest

    dccp-cooling-failure-manifest<TAB>2<TAB>store=<id><TAB>head=<u64><TAB>head_digest=<hex><TAB>parent=<u64><TAB>parent_digest=<hex><TAB>commit=<u64><TAB>floor=<u64><TAB>epoch=<u64><TAB>incarnation=<u64><TAB>bytes=<u64><TAB>retained=<n><TAB>attempt=<m>
    retained<TAB>ordinal=<u32><TAB>generation=<u64><TAB>digest=<hex><TAB>parent=<u64><TAB>parent_digest=<hex><TAB>commit=<u64><TAB>bytes=<u64>
    attempt<TAB>mutation=<id><TAB>ordinal=<u32><TAB>request=<hex><TAB>generation=<u64><TAB>digest=<hex><TAB>commit=<u64>
    count=<n><TAB>attempt=<m><TAB><sha256-hex>

`head` is the generation number of the committed head.
`parent` is the generation the head was derived from (0 for a first publication).
`retained` entries are emitted newest first; the head is ordinal 0.
`epoch` and `incarnation` identify the writer that committed the head,
so a successor can detect that it inherited a store it did not write.
The digest covers every preceding byte including the LF that terminates the last
attempt line.

**The replay table.** The `attempt` records are the accepted-attempt records this
authority carries, newest generation first. Each one is the identity of a mutation
(`mutation`), the 1-based `ordinal` it was accepted under, and `request`: the
digest of the canonical encoding of the request body with the generation and
parent generation zeroed (`request_content_digest`, section 2.4). The `generation`,
`digest` and `commit` fields are the committed result a retry is answered with.

**Why the table is here.** The durable replacement of this record is the single
commit point of a publication. A record written after that point could be lost by
a crash while the mutation it describes stayed committed, and a lost-response
retry of such a mutation would then be treated as a new mutation and publish a
second generation. Inside the manifest there is no such interval: the mutation
and the record that makes its retry a replay become visible together, or neither
does, through one atomic directory-entry replacement.

**The replay window.** A record is carried while the generation it names is still
retained, and the table holds at most `min(retained_generations,`
`idempotency_retention)` records. The window is therefore a property of the
committed bytes rather than of any later write, and it is bounded and
deterministic: an identity stays replayable for exactly as many publications as
both retention settings allow, and then its record goes with the generation it
named. A retry inside the window is answered with the committed result before any
stale precondition is judged, whatever crash boundary the previous attempt
reached and however many times the store has been reopened. Outside it, a retry
is a new mutation, and the ordinal rule of step 2 still refuses a reused identity
whose ordinal has gone backwards.

Each accepted attempt keeps its own record, because the ordinal is what makes it
a distinct operation; two records for one identity are distinct precisely when
their ordinals differ, and two records for one identity and one ordinal are
refused as corruption.

Version 1 of this record has thirteen header fields, no `attempt` group and no
trailer `attempt=`; it is still read, so a store written by release 1.0.0
opens, and its next publication writes version 2.

### 2.3 generation file

    dccp-cooling-failure-generation<TAB>1<TAB>store=<id><TAB>generation=<u64><TAB>digest=<hex><TAB>bytes=<u64><TAB>count=<u64><TAB><sha256-of-body>
    <body>

`<body>` is exactly the canonical state encoding of section 1 and is
`bytes` bytes long. `digest` is the state digest. The outer
`sha256-of-body` covers the body bytes only; it is a second, independent
check so that a truncated or extended body is detected even when both files
disagree about their own length. The body must begin immediately after the LF
that ends the header line and must end at end of file.

### 2.4 idempotency record

The record a retry is answered from is the replay record of section 2.2: it lives
in the committed manifest, crosses the commit point with the mutation it
describes, and is the authority. `request` is the digest of the canonical encoding
of the request body the attempt carried, so a replay with different content is an
IdempotencyConflict rather than a replayed success.

Release 1.0.0 kept this record in a file of its own:

    dccp-cooling-failure-attempt<TAB>1<TAB>mutation=<id><TAB>ordinal=<u32><TAB>request=<hex><TAB>generation=<u64><TAB>digest=<hex><TAB>commit=<u64><TAB>count=<u64><TAB><sha256-hex>

Those files are still read, after the committed manifest, so an upgraded store
answers a retry whose record predates the upgrade. They are never written, and a
file that disagrees with the committed manifest about an identity the manifest
does answer is reported by verification rather than resolved.

### 2.5 Publication protocol

The single commit point is the durable replacement of `manifest`.

1. Validate the request shape and the body (validate_structure + canonical
   encode + digest).
2. Resolve idempotency before any authority fence: if a record for
   (mutation, ordinal) exists and its request digest equals this request's, the
   stored receipt is returned with `replayed = true` and nothing is
   written. If the record exists with a different request digest, the call fails
   with IdempotencyConflict.
3. Fence: a supplied epoch must equal the handle epoch; a supplied incarnation
   must equal the handle incarnation; a supplied base generation must not EXCEED
   the committed head. A base below the committed head is accepted and the
   publication becomes a new mutation over newer state, because a caller that
   planned against an older generation is describing a real state this store once
   held; a base above the committed head names state the store never published and
   is refused. A violation is StaleAuthorityEpoch, StaleWriterIncarnation or
   StaleBaseGeneration. A fence is never applied to a replay.
4. Refuse a fresh publication while an attempt in the head is unresolved
   (AttemptOutstanding). Explicit reconciliation is the only way through.
5. Reserve generation = head + 1 and commit sequence = head commit + 1, both
   checked for exhaustion.
6. Write the generation file into `staging/` with a unique staged name,
   flush it durably, read it back, verify its digest, and re-derive the body's
   canonical fixed point. A mismatch removes the staged file and fails.
7. Atomically rename the staged file to `generations/g<gen>.dat`.
8. Write `manifest.prev` with the *current* manifest bytes verbatim
   (skipped when no manifest exists yet).
9. Durably write the new `manifest`, whose replay table now carries this
   publication's accepted-attempt record. **This is the commit point**; the
   mutation and the identity that makes its retry a replay become durable
   together.
10. Durably write `floor` with floor = min(committed floor so far).
11. Retire generation files below the retention window, remove `staging/`
    residue that is not referenced by the new head, and evict `idem/` files left
    by release 1.0.0 beyond the retention window.

Nothing is written after the commit point that a retry depends on.

Crash behaviour:

* Crash before 9: the head is unchanged and no replay record exists, so a retry
  of the same identity performs exactly one mutation. The new generation file is
  an orphan (newer than the head, unreferenced). It is reported by verification
  and removed by the next successful publication or by recovery. It is never
  adopted.
* Crash after 9: the head is committed and its replay record is committed with
  it. A retry of the same identity and the same intent is answered with the
  committed result, resolves before the epoch, incarnation, generation and binding
  fences, and publishes nothing. A retry with a different intent is
  IdempotencyConflict. This holds at every boundary from the atomic replacement
  onwards: immediately after the replacement, after the in-memory head moved,
  before and after the floor, after cleanup, and after the call returned.
* Crash after 9 before 10: the head is committed; the floor is behind but is
  still monotone (it is only ever lowered to the committed head when the head is
  ahead, and that direction is refused). Recovery re-derives it.

### 2.6 Recovery

`recover()` adopts `manifest.prev` only when the current
`manifest` cannot be verified. It never adopts anything below the durable
floor, never adopts an orphan generation file, and never adopts
`manifest.prev` when it is identical to `manifest` (that would adopt
nothing and would be reported as RecoveryUnavailable instead of a false
success). Every step it took is listed in the report.
