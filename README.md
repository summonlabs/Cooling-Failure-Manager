# Cooling Failure Manager

Generation-bound cooling-failure classification, response-plan and recovery-gate
authority over synthetic cooling evidence. This is DCCP boundary 54.

**Cooling Failure Manager 1.0.0** answers one question:

> Given current cooling and thermal failure evidence and the service obligations
> of the affected scopes, what cooling failure state is authoritative, which
> scopes are affected, what protective response is justified, and what current
> evidence is required before recovery?

It answers that question from evidence a caller supplies, and it publishes the
answer as an immutable generation it can defend: the classification, the affected
scope set, the response that is eligible, the protective restrictions in force,
the recovery gates and their verdicts, and the exact channels whose evidence is
missing. It never touches cooling equipment.

---

## Contents

- [Systems boundary](#systems-boundary)
- [What it does not do](#what-it-does-not-do)
- [The five facts that stay separate](#the-five-facts-that-stay-separate)
- [Build, test and install](#build-test-and-install)
- [Quick start](#quick-start)
- [The failure taxonomy](#the-failure-taxonomy)
- [Classification rules](#classification-rules)
- [The response plan](#the-response-plan)
- [Recovery gates](#recovery-gates)
- [Authority, generations and fencing](#authority-generations-and-fencing)
- [The durable store](#the-durable-store)
- [The canonical encoding](#the-canonical-encoding)
- [Scenario files and cfmctl](#scenario-files-and-cfmctl)
- [Determinism and reproducibility](#determinism-and-reproducibility)
- [Trust model and limits](#trust-model-and-limits)
- [Repository layout](#repository-layout)
- [Testing](#testing)
- [Benchmarks](#benchmarks)
- [License](#license)

---

## Systems boundary

### It owns

- **Cooling failure classification.** The closed taxonomy in
  include/dccp/cooling_failure_manager/enums.hpp, the witness rule for every
  class, and the verdict Confirmed, Suspected, Contradicted, Unsupported or
  Unknown for every class on every declared scope.
- **The affected scope set.** Which declared scopes the classification applies
  to, including the scopes that depend on a lost upstream scope, derived from
  the dependency shares the scopes themselves declare.
- **Response-plan state.** What response is eligible, what was solicited, what
  was acknowledged, what effect was observed, and what effect was verified.
- **Protective restrictions.** Which bounds are in force on a scope, and which
  failures release each one.
- **Recovery gates.** The proof obligations a recovery must present, and the
  verdict Permitted, Deferred or Blocked with the remaining interval named.
- **Generation-bound authority.** The topology, capacity, policy, incident and
  failure-domain generations a decision was made against, and the fencing that
  refuses a decision made against state that has moved on.
- **Durable attempt and evidence history.** Immutable generations, the accepted
  attempt records that make a retry a replay, and the crash protocol that makes
  a half-written generation impossible to adopt.

### It composes, and does not own

| Component | What this library takes from it |
|---|---|
| Cooling Topology | Scope identity and the declared cooling graph, as bindings and as this component's own projection |
| Cooling Capacity | Declared demand and measured capacity, as declared quantities and readings |
| Airflow Control | Airflow and containment state, as observations |
| Liquid Cooling Control | Flow, pressure, pump, valve and CDU state, as observations |
| Thermal Zone Manager | Thermal margin and supply temperature, as observations |
| Cooling Failover | Which cooling source is serving a scope; this library requests failover and never selects it |
| Thermal Emergency Manager | Thermal-safety policy; this library must not duplicate it |
| Incident State Fabric | Incident identity and lifecycle; this library references incidents and does not manage them |
| Facility Failure Domain Registry | Failure-domain identity and membership |

## What it does not do

- **No actuation.** Every response is a bounded request recorded against a
  decision. The library has no code path that commands equipment.
- **No measurement.** Every reading is supplied by a caller. The library never
  reads a sensor, a BMS, a chiller, a CDU, a CRAH or a file the caller did not
  name.
- **No capacity arithmetic.** It compares a measured reading against a declared
  bound. It never computes a heat budget, a load forecast or a flow balance.
- **No thermal-safety policy.** Safety thresholds belong to Thermal Emergency
  Manager. This library records the policy it was given and applies it.
- **No workload scheduling or placement.** It may request that load be reduced;
  the owner of placement decides what that means.
- **No generic incident or recovery lifecycle.** Those belong to Incident State
  Fabric and Recovery Coordinator. This library owns the cooling-specific gates.

## The five facts that stay separate

The component's central discipline is that five things which are easy to confuse
are kept apart in the type system, in the state, and in the canonical encoding:

1. **Eligibility** - the evidence justifies this response.
2. **Solicitation** - this component asked for it, with an idempotency key.
3. **Acknowledgement** - the addressee accepted the request.
4. **Observed effect** - an observation is consistent with the intended effect.
5. **Verified effect** - the effect was verified against that observation and a
   verdict was recorded.

An acknowledgement moves a plan forward by exactly one step. It never becomes an
effect. There is no code path that promotes one to the next.

Two more separations are just as strict:

- **A missing reading is unknown, never healthy and never zero.** There is no
  zero-valued placeholder anywhere. Quantity has no value at all when it is
  indeterminate, and its accessor refuses rather than returning 0.
- **A recovered reading is not a recovered capability.** Freshness, availability,
  quality and usability are four independent facts, and time passing is not
  evidence.

---

## Build, test and install

Requirements: a C++20 compiler and CMake 3.20 or newer. Nothing else is
downloaded, vendored or linked.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build && ctest --output-on-failure
```

Install into a prefix:

```sh
cmake --install build --prefix /path/to/prefix
```

Consume it from another project:

```cmake
find_package(cooling_failure_manager 1.0 REQUIRED)
target_link_libraries(app PRIVATE dccp::cooling_failure_manager)
```

### Options

| Option | Default | Effect |
|---|---|---|
| COOLING_FAILURE_MANAGER_BUILD_TESTS | ON | Build the test suite |
| COOLING_FAILURE_MANAGER_BUILD_TOOLS | ON | Build the cfmctl inspection tool |
| COOLING_FAILURE_MANAGER_BUILD_EXAMPLES | ON | Build the five examples |
| COOLING_FAILURE_MANAGER_BUILD_BENCHMARKS | ON | Build the benchmark suite |
| COOLING_FAILURE_MANAGER_WARNINGS_AS_ERRORS | ON | Treat first-party warnings as errors |
| COOLING_FAILURE_MANAGER_ENABLE_ASAN | OFF | Build with AddressSanitizer |

Only the library and cfmctl are installed.

## Quick start

A scope declares what normal means for it. Evidence is recorded against it. One
evaluation turns the two into a decision.

```cpp
#include "dccp/cooling_failure_manager/decision.hpp"
#include "dccp/cooling_failure_manager/evidence.hpp"

namespace cfm = dccp::cooling_failure_manager;

// 1. Declare the scope and the bounds its owner is accountable for.
cfm::CoolingScope loop;
loop.id = *cfm::ScopeId::parse("loop.a");
loop.kind = cfm::ScopeKind::Loop;
loop.policy.envelope.min_flow = *cfm::DeclaredQuantity::make(30000, "mL/s");
loop.policy.requirements.push_back(
    {cfm::ObservationChannel::FlowMeter, cfm::DurationMilliseconds(60000)});

// 2. Record synthetic evidence. A real deployment feeds this from its own
//    components; nothing here is measured by the library.
cfm::ObservationSet observations;
cfm::Observation reading;
reading.id = *cfm::ObservationId::parse("obs.1");
reading.scope = loop.id;
reading.channel = cfm::ObservationChannel::FlowMeter;
reading.quantity = *cfm::Quantity::observed(0, "mL/s", cfm::ObservationQuality::Good,
                                           cfm::ObservationSequence(1));
reading.observed_at = cfm::DecisionClock(999000);
reading.recorded_at = cfm::DecisionClock(999000);
reading.producer = "loop-flow";
reading.sensor = "fm-1";
reading.evidence_generation = cfm::EvidenceGeneration(1);
(void)observations.add(reading);

// 3. Evaluate.
cfm::CoolingFailureState skeleton;
skeleton.evaluated_at = cfm::DecisionClock(1000000);
skeleton.scopes.push_back(loop);

cfm::DecisionPolicy policy;
policy.evidence_window = cfm::DurationMilliseconds(60000);

cfm::DecisionInput input;
input.prior = &skeleton;
input.observations = &observations;
input.policy = policy;
input.clock = cfm::DecisionClock(1000000);

cfm::Result<cfm::DecisionOutcome> outcome = cfm::evaluate(input);
if (!outcome.has_value()) {
  // Every failure is a value, never an exception.
  report(outcome.error().code(), outcome.error().message());
} else {
  for (const cfm::ScopeDecision& decision : outcome->state.decisions) {
    for (const std::string& line : decision.explanation) {
      log(line);  // stable, machine-readable lines
    }
  }
}
```

See examples/ for complete programs, including one that publishes to a durable
store and one that recovers from a crash with a request in flight.

---

## The failure taxonomy

Fifteen classes, closed. A producer cannot invent a sixteenth, which is what
keeps classification, response eligibility and recovery gates in one taxonomy.

| Class | Severity | Urgency | Total loss | Forces a restriction |
|---|---|---|---|---|
| plant-loss | Critical | Immediate | yes | yes |
| pump-failure | Impaired | Imminent | no | yes |
| loop-degradation | Degraded | Elevated | no | no |
| loop-loss | Total | Immediate | yes | yes |
| chiller-failure | Impaired | Imminent | no | yes |
| cdu-failure | Critical | Immediate | yes | yes |
| valve-flow-failure | Impaired | Imminent | no | yes |
| pressure-failure | Impaired | Elevated | no | yes |
| crah-crac-failure | Impaired | Imminent | no | yes |
| airflow-loss | Critical | Immediate | no | yes |
| containment-breach | Impaired | Imminent | no | yes |
| leak | Critical | Immediate | no | yes |
| thermal-capacity-loss | Impaired | Elevated | no | yes |
| shared-source-failure | Critical | Immediate | yes | yes |
| thermal-runaway | Critical | Immediate | yes | yes |

**Total loss** is a narrow property, and it is the one that decides attribution:
only a class that means the scope has lost its cooling function entirely is
attributed to the scopes that depend on it. A single failed chiller unit inside a
live plant, a single failed air-handling unit, a failed pump set, a valve or
pressure fault, a containment breach, a leak and a capacity shortfall are all
degradations of a scope that is still functioning, and attributing any of them
downstream would report a loss that did not happen.

## Classification rules

Every class has a declarative rule: a set of witness channels, each with a role
(Direct, Supporting or Refuting) and a signal (below a declared floor, above a
declared ceiling, outside a declared envelope, dead, a status code, or a leak
state). The rule table is a compile-time constant that tests pin, so a class can
never quietly change what it means.

Four rules decide the verdict, and all four are load-bearing:

1. **A Direct witness must trigger.** Supporting witnesses can never add up to a
   confirmation, however many of them there are.
2. **A supporting witness only counts once the class's own primary witness has
   been observed.** Otherwise one generic channel would raise a suspicion of
   every class that lists it: a low flow would be reported as a suspected CDU
   failure, valve failure and pump failure at once, though none of those units
   was ever observed.
3. **The reading must be current.** Something that was true ten minutes ago is
   not a statement about now. A stale dead flow neither confirms a loss nor
   argues against one; the class is Unknown until fresh evidence arrives.
4. **An undeclared limit is not a violated limit.** A scope that declares no
   flow floor can still have a loop loss confirmed by a dead flow, because zero
   flow needs no declared limit to be a fact. It cannot have a degradation
   confirmed, because a merely low reading against no declared floor is not a
   violated bound.

The verdict for each class is one of:

- **Confirmed** - a Direct witness triggered on current, usable evidence and the
  policy's demand for independent producer streams is met.
- **Suspected** - a witness triggered but the evidence is not sufficient to
  confirm, reported one severity step below its confirmation.
- **Contradicted** - every evaluable witness argues against the class.
- **Unsupported** - the class cannot be evidenced at all with the declared
  envelope, because the witness needs a bound the scope never declared.
- **Unknown** - nothing usable has been observed.

None of the last four is health. A class is never Healthy unless the evidence
positively supports normal cooling for it, and the decision lists every channel
whose evidence is not current so an operator can see what is missing rather than
infer it.

### Evidence quality

- A reading that does not exist is **Indeterminate** and is never usable.
- A reading whose producer marked it Suspect or Bad cannot confirm a failure and
  cannot satisfy a recovery gate. It is still recorded and still participates in
  conflict detection.
- Two producers reporting the same sequence number with different readings are
  **Conflicting**: the component reports the disagreement instead of choosing.
- A reading dated after the decision clock is **Future**, its age is reported as
  a negative number, and it is not current evidence.
- An observation that is carried forward keeps its own sampling time; it never
  ages forward into freshness.

## The response plan

Eligibility is derived from the confirmed classes, never from caller intent. A
solicitation is refused with **PlanNotEligible** when the action the caller
wants is not one the evidence justifies.

A confirmed class escalates immediately when the class carries a safety
escalation. A suspicion is answered with evidence gathering, load reduction and
the bounded protections that do not presume the failure is real.

Protective restrictions are bounds rather than actions: a load ceiling, no new
work, no capacity commitment, an isolated coolant path, held containment,
reserved standby and a manual hold. Every restriction names the failures that
release it, so releasing one is a decision about evidence rather than an
omission. A restriction is released only by a recovery assessment that reached
Permitted.

### What it never does

An attempt that was in flight when its owner stopped is moved to **Unresolved**
exactly once, and it is never redispatched. While any attempt of a scope is
unresolved, a new solicitation for that scope is refused with
**AttemptOutstanding**; while any attempt in a published state is in flight, a
publication that changes none of them is refused at the store boundary with the
same code. The way forward is always an explicit report or reconciliation.

## Recovery gates

Twelve named proof obligations. Each is evaluated against evidence that is
current at the decision clock, and the verdict is one of three, never collapsed:

- **Permitted** - every gate passed on current evidence.
- **Deferred** - every gate that can be checked now passed, but a dwell or
  hysteresis interval is still running; the assessment reports how long is left.
- **Blocked** - at least one evidence gate failed, and the assessment names it.

A gate applies to a scope only when the recovery demand, the scope's own declared
evidence requirements, or one of the classes being cleared names its channel. A
gate that does not apply is reported as satisfied with the reason stated, so it
is visibly considered and waived rather than forgotten. Without that rule a
scope that does not instrument containment could never recover.

The gates are: flow known, pressure known, leak clear, thermal capacity restored,
thermal margin restored, airflow restored, containment restored, confirmed classes
cleared, effect verified, evidence current, dwell elapsed, hysteresis elapsed.

Two of them carry the weight of the component's argument:

- **Leak clear** requires a positive assertion. A missing or unknown leak state
  never clears it, which is why a recovery demand that implicates a leak demands
  the leak channel at all.
- **Confirmed classes cleared** applies exactly the same predicate that would
  confirm the class. A class whose witness still satisfies its null signal has
  not cleared, whatever the wall clock says.

Nothing is inferred from elapsed time. A scope whose evidence has gone stale is
Blocked, not Recovered.

---

## Authority, generations and fencing

Every decision records the bindings it was made against: the cooling topology,
capacity, policy, incident, failure-domain and control-plane generations a caller
supplied. A binding is an owner, an identity and a generation, and two bindings
are equal only when all three match. This library never advances an owner's
generation; it reports when the owner has moved on.

Messages are recorded as stable tokens, never as prose, so an authority that has
moved on is a value a caller can branch on:

- **StaleAuthorityEpoch** - the mutation was planned under a superseded epoch.
- **StaleWriterIncarnation** - under a superseded incarnation of the epoch.
- **StaleBaseGeneration** - against a generation this store never committed.
- **StaleDecision** - a decision whose bindings no longer match what is supplied.

A stale binding forbids a recovery but never forbids an escalation: dead coolant
does not become safe because a topology reference is out of date.

### Idempotency and replay

A mutation is identified by a caller-supplied MutationId and a 1-based attempt
ordinal. Repeating the pair with the same content returns the recorded outcome
and writes nothing; repeating it with different content is an
**IdempotencyConflict**. A replay is resolved *before* the authority fence, which
is what makes a lost response safe: a caller that retries an operation that was
already committed is told so instead of being forced to plan it again.

Retention is bounded. An attempt whose record has been evicted is no longer
recognisable as a replay, and the next request that reuses its identity is
treated as a new mutation. A caller that cannot know the window must use a fresh
identity rather than rely on replay.

## The durable store

The store keeps immutable generations of cooling-failure state with one
authoritative head manifest. Its layout, encoders and protocol are specified byte
by byte in **docs/FORMATS.md**; the summary is:

- generation files are write-once and verified on every read;
- the **single commit point** is the durable replacement of the head manifest;
- the writer lock is an operating-system exclusive lock held for the life of the
  handle and released by the kernel when the process dies;
- a crash before the commit point leaves an orphan generation that verification
  reports and recovery removes, and which is *never* adopted;
- a crash after it leaves a committed generation that reopens verified.

```cpp
cfm::StoreOptions options;
options.root = "/var/lib/cooling-failure/store";
cfm::Result<cfm::Store> store = cfm::Store::open(options);

cfm::PublicationRequest request;
request.epoch = store->epoch();
request.incarnation = store->incarnation();
request.mutation = *cfm::MutationId::parse("loop-a.recover.1");
request.attempt = *cfm::AttemptOrdinal::parse(1);
request.body = outcome->state;
cfm::Result<cfm::PublicationReceipt> receipt = store->publish(request);
```

**Durability is never assumed.** Every entry point that can order bytes through
the storage device takes an explicit durable flag, and a receipt says
**NotDurable** when durability was not established rather than claiming it.

**Recovery is conservative.** A store adopts the previous committed publication
only when the current head cannot be verified, never adopts anything below the
durable generation floor, and never adopts an orphan. Every step it took is
listed in the report; a refusal is an error, so a successful report never
describes a store that is still broken.

### Crash behaviour, measured

The test suite kills a real child process at each publication boundary and
reopens the store from the parent. At **publish.after-stage** and
**publish.before-rename** the new generation is not committed and is left as
staged residue; at **publish.after-rename** and **publish.before-manifest** it is
an orphan, reported and never adopted; at **publish.after-manifest** and every
later stage the generation is committed. At every one of the nine stages the
store reopens, head() returns a fully verified state, verify() reports no defect,
a second reopen yields the same head and digest, and the next publication commits
exactly head + 1 with no residue.

## The canonical encoding

One state has exactly one spelling. The format is line-oriented, versioned and
digest-terminated:

```
dccp-cooling-failure-state	1	generation=0	parent=0	clock=1000000
state	bindings=1	scopes=1	failures=2	plans=1	evidence=3	decisions=1	unresolved=0
binding	role=cooling-topology	owner="cooling-topology"	identity="site.a"	generation=4
...
end	128	2760ed7b799a5fbc4c2dc50a55c5d0ed91845dd8cf254e269973966642af2dd4
```

- Records are emitted in a fixed order and, within a group, in the canonical
  order that canonicalize() establishes, so two states that differ only in
  insertion order encode to identical bytes.
- Every free-text field is escaped, so a record can never contain the separator.
- Numbers are canonical decimal and enumerations are their stable tokens; an
  unknown token is refused rather than defaulted.
- The last line carries the record count and a digest over every preceding byte,
  so truncation, duplication and reordering are all detected.
- An absent clock is an empty field, which is the format's single spelling of
  not set; a negative clock is not a canonical value and is refused.

Decoding is strict and total. It verifies the format name and version, the field
vocabulary and parentage of every record, the count, the digest, the structural
validity of the decoded state, and finally that re-encoding reproduces the
identical bytes. It never repairs and never guesses.

---

## Scenario files and cfmctl

cfmctl inspects durable state and turns a synthetic scenario into a decision. It
never actuates anything.

```sh
cfmctl version
cfmctl evaluate --scenario=scenario.cfm --explain
cfmctl evaluate --scenario=scenario.cfm --canonical
cfmctl evaluate --scenario=scenario.cfm --publish --store=/path/to/store \
       --mutation=run.1 --attempt=1
cfmctl inspect --store=/path/to/store
cfmctl inspect --store=/path/to/store --verify
cfmctl explain --store=/path/to/store --scope=loop.a
cfmctl recover --store=/path/to/store
cfmctl reconcile --store=/path/to/store --mutation=run.1 --attempt=1
```

Exit codes are part of the contract: 0 succeeded, 1 ran but the answer is
negative, 2 the command line was wrong, 3 the input could not be read or decoded.

### The scenario format

Line-oriented, ASCII, one assignment per line. A '#' starts a comment; blank lines
are ignored; a 'key = value' pair belongs to the section currently open, or is
global when no section is open. An unknown section, key or enumeration token is
an error, never a default.

```ini
# Global: the decision clock, the evidence window and the policy.
clock = 1000000000
evidence-window = 60000
confirm-min-observations = 1
require-direct-witness = true
safety-escalation-severity = critical
binding = cooling-topology=cooling-topology:site.a:4
observed-binding = cooling-topology=cooling-topology:site.a:4
authority-changed = false

[scope]
id = loop.a
kind = loop
name = Primary loop
min-flow = 30000:mL/s
min-differential-pressure = 50000:Pa-dp
declared-demand = 2000000:W
min-thermal-margin = 2000:mK
max-supply-temperature = 25000:mC
dwell = 300000
hysteresis = 120000
service-severity-floor = degraded
require = flow-meter:60000
strict-class = leak
depends-on = plant.a:supplies-coolant:1000000

[observation]
id = obs.flow.1
scope = loop.a
channel = flow-meter
value = 0
unit = mL/s
quality = good
sequence = 1
at = 999999000
producer = loop-flow
sensor = fm-1
evidence-generation = 1

[observation]
id = obs.leak.1
scope = loop.a
channel = leak-detector
leak = leak-active
at = 999999000
producer = loop-leak

[solicitation]
scope = loop.a
mutation = run.1
attempt = 1
action = start-standby-pump
addressee = liquid-cooling-control

[attempt-report]
attempt = at.loop.a.run.1.1
state = acknowledged
at = 1000000000

[recovery-request]
scope = loop.a

[stable-since]
scope = loop.a
since = 999999000
```

A scalar reading must carry the unit of its channel; a status or leak channel
must not. A reading that does not exist is written with indeterminate = true.

---

## Determinism and reproducibility

An evaluation is a pure function of its inputs. It reads no clock, no
environment, no file and no global state, so the same inputs always produce the
same state and the same explanation bytes. The tests enforce this by evaluating
the same scenario twice and comparing the canonical encodings byte for byte, and
by recording the same observations in two different orders and comparing again.

Consequences a caller can rely on:

- decisions can be recomputed and diffed, so a disputed classification can be
  reproduced exactly;
- explanations are stable lines rather than prose, so they can be filtered and
  compared;
- a state can be stored, transmitted and verified by digest;
- a test failure is reproducible from a seed and a case name alone.

## Trust model and limits

**This library is an authority on classification and a gate on recovery. It is
not a safety system, a control system or an integrity boundary against a
determined local attacker.**

- It performs no actuation and drives no equipment. A cooling action happens only
  because some other component, acting on its own authority, decided to take it.
- It cannot verify that a producer told the truth. It records what it was told,
  with provenance and quality, and reports disagreement rather than resolving it.
- It classifies synthetic and caller-supplied evidence. It makes no claim about
  any live BMS, chiller, CDU or CRAH.
- SHA-256 is used as an integrity check against corruption and accidental
  substitution, not as a defence against an attacker who can rewrite the store.
  The store root is assumed to be owned by the operator and not world-writable.
- Path checks defend against accidental substitution and naive path attacks. A
  process that can replace entries inside the store directory at the exact moment
  of a call is outside the trust model.
- Durability is reported, never assumed. A receipt that says NotDurable means
  exactly that.

### Genuine limitations

- **One decision clock per evaluation.** A scenario evaluated over a long window
  must be re-evaluated with a later clock; the library does not interpolate.
- **Retention is bounded and eviction is documented.** An idempotent replay is
  guaranteed only while its accepted-attempt record is retained.
- **The idempotency record is written immediately after the commit point.** A
  crash in that window leaves a committed publication whose retry is treated as a
  new mutation. The window is kept as small as the protocol allows and is
  documented in docs/FORMATS.md.
- **Attribution uses the maximum share over the dependency paths it finds.** A
  dependency declared with a share of zero does not carry cooling and is not
  traversed, and a scope reached by several paths keeps the strongest.
- **A cancellation of a deferred wait is not modelled.** A dwell that has started
  either completes or is replaced by a new stable_since; the library does not
  remember a cancelled interval.

---

## Repository layout

```
include/dccp/cooling_failure_manager/   the public API, 14 headers
  enums.hpp         the closed taxonomies and their stable tokens
  result.hpp        ErrorCode, Error, Result
  strong_id.hpp     validated identities and the distinct counters
  limits.hpp        every bound, in one place
  model.hpp         bindings, scopes, failures, plans, decisions
  evidence.hpp      Quantity, Observation, ObservationSet, DecisionPolicy
  classify.hpp      the failure rule table and witness evaluation
  decision.hpp      the evaluation engine's inputs and outputs
  recovery.hpp      the recovery demand and gate verdicts
  canonical.hpp     the canonical encoding
  store.hpp         the durable store
  text.hpp digest.hpp version.hpp
src/                  the implementation, 18 translation units
tests/                233 cases, including real multi-process and crash tests
examples/             five complete programs
benchmarks/           measured throughput with provenance on every line
tools/cfmctl/         the inspection and evaluation tool
docs/FORMATS.md       the byte-level format and store protocol contract
```

## Testing

233 cases, no timeouts and no sleeps in the framework, deterministic under a
seed:

```sh
cd build && ctest --output-on-failure
./cooling_failure_manager_tests --seed=12345
./cooling_failure_manager_tests --filter=store_process
```

What the suite proves, by area:

- **Foundation** - SHA-256 against the standard vectors and an independent second
  implementation; UTF-8 acceptance and rejection tables; the escape codec against
  every byte string; the identifier grammar against an independent reference
  model over 20000 randomized candidates; every enumeration token round-tripping.
- **Evidence and classification** - every documented rejection with its exact
  code; the rule table's internal consistency pinned at compile time; randomized
  proofs that a witness is never simultaneously triggered and contradicting.
- **Decision engine** - classification, eligibility, restrictions, the attempt
  state machine, shared-source attribution and the lifecycle, each with the
  negative case that must not happen.
- **Recovery** - every gate in every state, including the gates that do not apply,
  the deferred interval, and the proof that a stale reading is not a recovery.
- **Canonical encoding** - a round trip over a state with every table populated,
  byte-exact preservation of escaped text, and refusal of a single flipped byte at
  *every* offset of the encoded body.
- **Store** - lifecycle, exclusive locking, the generation chain, integrity
  failures, the floor, retention, history, fencing, and idempotent replay.
- **Multi-process** - a second process refused the writer lock; an abrupt death
  releasing a kernel-owned lock; a successor with strictly greater authority; and
  crash injection at nine publication boundaries, each reopening into one of two
  fully verified states.
- **Integration** - the invariants that only hold if the parts agree: an absent
  reading never becomes healthy, an acknowledgement never becomes an effect, and
  a recovery is never inferred from elapsed time.
- **Adversarial** - every single-byte mutation of a canonical body, framing damage,
  duplicate identities, dependency cycles, dangling references, hostile store
  roots, corrupt generation files, and absurd configurations.

## Benchmarks

Every benchmark reports completed useful operations per second, never the cost of
submitting work, and prints its provenance on every line:

```sh
./cooling_failure_manager_benchmarks 2000 /path/to/scratch/store
```

The cooling evidence and the facility it describes are **synthetic**; the
processes, the clock and the file system are **real**. The durable figures include
the device flush and the read-back verification the library performs, so they
depend on the storage device and are reported with that context rather than as a
universal number.

Measured on the reference machine used for release validation (16 logical cores,
Release, Ninja, local SSD), 2000 iterations of each in-memory operation and 200 of
each durable one:

| Benchmark | Result | Scale | Provenance |
|---|---|---|---|
| decision.evaluate | 121 op/s | 64 loops, 3 channels each; 709035-byte state | SYNTHETIC facility |
| canonical.encode | 254 op/s | 709035 canonical bytes | SYNTHETIC state |
| canonical.decode+validate | 83 op/s | 709035 canonical bytes | SYNTHETIC state |
| canonical.digest | 173 op/s | 709035 canonical bytes | SYNTHETIC state |
| evidence.latest | 1594939 op/s | 195 observations | SYNTHETIC observations |
| recovery.evaluate | 65365 op/s | 12 gates | SYNTHETIC evidence |
| store.publish.durable | 9.2 op/s | 200 committed generations | REAL file system, durable flush |
| store.head.verify | 48.9 op/s | 200 verified heads | REAL file system |
| store.verify.deep | 2.8 op/s | 200 deep verifications | REAL file system |

The figures are a property of this machine and this storage device, not a
guarantee. Reproduce them on your own hardware before relying on any of them.

### Static analysis and sanitizers

The release validation runs three independent checks, and all three are reported
whatever they find:

- **MSVC static analysis** (`/analyze`, the whole library) reports two
  diagnostics, both of which were investigated: an annotation-precision warning in
  the SHA-256 compression loop, where the analyzer cannot prove the block index
  stays inside the 64-byte block even though the loop condition makes it
  impossible for it not to; and a stack-size estimate for `decode_state` that the
  analyzer inflates through inlined error construction. Neither is a defect, and
  neither is suppressed.
- **AddressSanitizer** (`-DCOOLING_FAILURE_MANAGER_ENABLE_ASAN=ON`) runs the
  whole 233-case suite. It found one real defect during validation: a test macro
  bound a reference to a value held inside a temporary `Result`, which left the
  reference dangling after the temporary died. The macro now compares by value.
- **`/W4 /WX`** on MSVC for the library, the tool, the examples, the benchmarks
  and the whole test suite, with zero warnings.

---

## License

Apache License 2.0. See LICENSE for the full text and NOTICE for attribution.
