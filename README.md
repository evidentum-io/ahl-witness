# ahl-witness

An independent witness for the [AHL Protocol](https://atl-protocol.org)'s `ahl-adaptor-atl-v1`
profile: the core spec §3.3 cosigning state machine, refusal evidence on equivocation, and
freshness reporting — the piece that makes conformance level L3 reachable on an ATL-backed log.

## Why this exists

Inclusion and consistency proofs establish consistency only within the view a verifier is
shown; a log operator can present different histories to different parties. The AHL core
specification therefore requires, at L3, at least one **independent witness** per log: a party
outside the producer's and operator's control that verifies each new checkpoint against the one
it already holds, countersigns it on success, publishes the result, and — when the log presents
something inconsistent — refuses and publishes signed evidence of the refusal (core spec §3.3).
The underlying ATL log has no witness role at all (adaptor profile §11), so this component is
what makes L3 reachable; without it, a corpus can be no more than L2.

## What this crate is not

It does not walk the statement graph (inputs, outputs, triggers, closure) and does not
interpret dataset, pipeline, or retention semantics — those are a verifier's job (core spec
§6). It does not serve entries or authenticated range enumeration — that is `ahl-mirror`'s and
any independent mirror's job (core spec §3.5). A witness's scope is narrowly the §3.3 state
machine: verify a checkpoint's authenticity and consistency, cosign or refuse, publish the
result, and report its own freshness.

## Architecture

A library (`src/lib.rs` and siblings) plus a thin binary (`src/bin/ahl-witness.rs`):

| module | responsibility |
| --- | --- |
| `metadata` | the fixed ATL adaptor metadata object (§4.2) and the log-tree leaf hash |
| `duration` | ISO 8601 duration parsing for `checkpoint_cadence`/`witness_grace_period` |
| `checkpoint` | the signed checkpoint object, its 98-byte ATL blob, and signature verification (§6) |
| `config` | genesis governance anchors (one per watched log) and the witness's own signing identity |
| `governance` | the verified governance chain walk: producer-signature and `predecessor` checks, checkpoint-signing key, cadence and grace-period resolution |
| `consistency` | classifying an offered checkpoint against the retained one |
| `witness` | the core spec §3.3 state machine: cosigning, refusal evidence, their signatures and verification |
| `freshness` | staleness of the latest cosigned checkpoint against cadence + grace period (§3.3 item 4) |
| `store` | durable storage for retained/cosigned checkpoints and published refusal evidence |
| `http` | the publication interface: submit a checkpoint to be witnessed, read cosigned checkpoints, refusal evidence, and freshness |

The binary loads a JSON deployment configuration (witness signing seed + one genesis anchor per
watched log + store path), opens the store, and serves the HTTP API. It does not itself poll a
mirror or log for new checkpoints — see "Feeding the witness" below.

## The state machine (core spec §3.3)

```text
1. Retain, per log, the latest checkpoint cosigned.
2. On a new checkpoint: verify the log's signature; verify a consistency proof from the
   retained checkpoint; on success, cosign, retain, publish.
3. On failure — inconsistency or missing proof — refuse to cosign and publish signed
   refusal evidence containing both conflicting checkpoints.
4. Freshness: a witness whose latest cosigned checkpoint is older than cadence + grace is
   stale; it must report itself so.
```

`witness::witness_checkpoint` is the single entry point implementing all four steps, plus the
normative **"obligations that make the machine sound"** core spec §3.3 added in a later round
(commit `92f8fc4`) — this section and the next three describe those obligations and exactly how
this crate meets each one. Given a candidate checkpoint, the complete ordered entry byte
sequence `[0, tree_size)` (needed to resolve governance — see below), and the current time, it
returns either `WitnessOutcome::Cosigned` or `WitnessOutcome::Refused`, or a `WitnessError` for a
candidate that never authenticated at all (see "Authentication failures are not refusal
evidence" in the module's doc comment for why that distinction matters and is drawn
deliberately).

Consistency between two specific checkpoints is decided by `consistency::check` without trusting
any externally-computed proof: given leaf hashes covering `[0, offered.tree_size)`, it
classifies the pair as `Consistent` (a genuine append-only extension, or an idempotent republish
at equal size and root), `Equivocation` (equal size with a different root), `SizeRegression` (a
smaller offered size), or `ExtensionFailed` (a larger offered size whose consistency proof was
generated but does not verify — the proof is carried in the outcome). A proof that cannot even
be *generated* is propagated as an error, never produced as a refusable outcome — see "Refusal
reason taxonomy" below for why.

## Equivocation ends the series (core spec §7.3 and §3.3)

Core spec §7.3: "Two authenticated members sharing a `tree_size` with differing `root_hash`
values are equivocation, not a tie … From the lowest `tree_size` at which it occurs, the series
is no longer canonical … Detecting equivocation and then continuing to serve one branch is a
conformance violation." Core spec §3.3 sharpens this into two obligations a witness must meet:

- **Compare against the whole retained history, not the newest member.** `consistency::check`
  only ever compares `offered` against one `retained` checkpoint, but a witness that used it
  against just the *latest* retained member would misclassify an offered checkpoint conflicting
  with an *older*, non-latest cosigned member as a harmless size regression and never notice the
  equivocation — exactly the failure mode a first implementation round of this crate had.
  `witness_checkpoint` therefore always queries the store for a previously cosigned checkpoint at
  the *exact* offered `tree_size` first (`store::find_cosigned_at_size`, scanning the complete
  cosigned history, not just the newest row); only once that query finds nothing does it fall
  back to comparing against the single latest retained checkpoint via `consistency::check`.
- **Equivocation is permanent for that log.** The first time either path finds a conflict, this
  crate records an **equivocation floor** and every later call for that log — however validly
  signed, however genuine an extension it might otherwise be — is refused without running
  ordinary consistency checking at all, so no later checkpoint can ever be cosigned in a way that
  would make either conflicting branch look canonical again. Refusals citing a standing floor
  reuse the *original* conflicting pair as evidence (not the new, unrelated candidate, which
  appears only in the free-text `detail` field) — see "Refusal reason taxonomy" for why that
  matters.

The read side, `witness::published_checkpoint`, is the query counterpart: once a log has an
equivocation floor, it reports `PublishedCheckpoint::Equivocated` (surfaced over HTTP as
`409 Conflict` on both `GET /v1/logs/{log_id}/checkpoint` and `.../freshness`) instead of the
latest retained row, however validly that row was itself cosigned before the divergence was
found.

## Serialization and atomicity (core spec §3.3)

"The retain–verify–classify–cosign transition MUST be serialized per log and atomic. Two
concurrent submissions extending the same retained state to different roots at the same size
MUST NOT both be cosigned; state MUST be re-read inside the critical section, and an equivocation
record MUST be persisted in the same atomic step as the refusal it justifies."

A first implementation round satisfied this only per individual `Store` call — the read, the
classification, and the write were each their own lock acquisition, so two concurrent requests
could both read the same pre-write state, both pass classification, and both be cosigned: the
witness itself would equivocate. The fix has two parts:

- **`Store::with_lock`** (crate-private) holds the store's one mutex for an *entire* decision —
  every read `witness_checkpoint` depends on, and the resulting write — rather than once per
  method call. `witness::transition` (crate-private) is the function that runs inside it: it
  re-reads the equivocation floor, the exact-size history match, and the latest retained
  checkpoint fresh, every call, and never trusts a value read before the lock was (re)acquired.
- **A real `SQLite` transaction** (`store::insert_equivocation_and_refusal`, via
  `Connection::unchecked_transaction`) wraps the two writes a fresh equivocation discovery
  requires — the `equivocations` floor row and the refusal evidence that justifies it — so they
  persist together or not at all, independent of the in-process lock (which protects against
  concurrent callers, not against a crash mid-write).

`witness::tests::concurrent_conflicting_extensions_at_the_same_size_equivocate_exactly_once`
exercises this from two real OS threads racing against one shared, `Arc`-wrapped `Store`,
synchronized with a `Barrier`, asserting the outcome shape (exactly one cosign, one
equivocation refusal, one floor) rather than which thread happens to win — which is legitimately
non-deterministic and, run repeatedly, was confirmed stable in outcome regardless.

## Refusal reason taxonomy (core spec §3.3)

"Every refusal reason MUST be independently checkable from the evidence it carries; a reason
whose verification procedure is undefined MUST NOT be emitted." `RefusalReason` has exactly
three members meeting that bar — this is the taxonomy the adaptor profile is expected to adopt:

| reason | when | what a verifier independently rechecks |
| --- | --- | --- |
| `equivocation` | `retained`/`offered` share a `tree_size` with different `root_hash` — found either at the offered size directly, or cited again (with the *original* pair) for every later candidate while the log's floor stands | `retained.tree_size == offered.tree_size && retained.root_hash != offered.root_hash` |
| `size-regression` | `offered.tree_size` is smaller than an already-cosigned size, with no history entry at the offered size itself | `offered.tree_size < retained.tree_size` |
| `extension-failed` | `offered.tree_size > retained.tree_size` and the carried purported extension proof fails verification | confirm `consistency_proof.from_size`/`to_size` equal `retained.tree_size`/`offered.tree_size` — a structurally valid failing proof for an *unrelated* pair of sizes MUST NOT validate this refusal — then rerun RFC 9162 verification against the two carried roots (`consistency::verify_extension_failure`) |

`extension-failed` means precisely **"the carried purported extension proof fails
verification"** — nothing more. It does not mean, and MUST NOT be described as, proof that no
valid extension exists between `retained` and `offered`: a witness can show one specific proof
fails, never that every proof would.

`witness::verify_refusal_claim` implements exactly this table and is unit-tested for all three
reasons, including a genuine replay of a carried `extension-failed` proof and a negative test
(`a_proof_for_an_unrelated_pair_of_sizes_does_not_validate_this_refusal`) confirming a
well-formed, genuinely-failing proof carrying the *wrong* sizes is rejected as evidence rather
than accepted.

Adaptor profile §11.2's `missing-consistency-proof` reason is **deliberately not part of this
taxonomy**. It is written as though a consistency proof is handed to the witness and can simply
be absent; this crate instead always supplies the complete `[0, offered.tree_size)` entry range
before classifying anything (adaptor profile §10.6), so a proof between two sizes it already
holds material for can only fail to *generate* for reasons that are not claims about the log's
checkpoints — there is no proof to carry, and nothing for a verifier to recheck. Such a failure
is propagated as a `WitnessError`, never emitted as a refusal reason, per the "MUST NOT be
emitted" clause above.

The prior taxonomy (`inconsistent` covering both size regressions and failed extensions
indistinguishably, plus `missing-consistency-proof`) failed this bar for size regressions and
failed extensions: a verifier holding only `retained`/`offered` could confirm an equal-size
conflict but could not, from two root hashes alone, distinguish "the log shrank" from "the
witness's extension proof failed" — nor recheck the second without the proof, which the old
schema never carried. That gap is what this round's taxonomy closes.

## Why enumerated governance, not a shortcut

Adaptor profile §10.6 states plainly that this profile provides **no typed-subset proofs**:
there is no capability that proves "these are all the manifest and key entries in this range"
without carrying the full range. A witness resolving governance from anything less than the
complete `[0, tree_size)` entry sequence could miss a key rotation or a manifest change and
silently trust a checkpoint signed by a retired key. `governance::resolve` therefore always
requires the full ordered entry sequence, exactly as `ahl-mirror`'s governance resolution does.
Resolution also enforces the revision itself: once a `manifest` or `key` statement's producer
signature verifies under the key set in force, the statement MUST declare the revision this
build verifies (`ahl_core::AHL_VERSION`, currently `0.4`), and one declaring an earlier
revision — or none at all — is refused by name (`UnsupportedStatementVersion`) rather than
skipped as one more unverified candidate, because revision 0.4 verifies no material issued
under an earlier revision (I-D §2.2, §7.1). Skipping it would silently leave the previous
governance version in force, which is a ruling on material this revision has no rules for. The
check runs on every candidate whose envelope verifies, before `predecessor`, `action` or any
other payload member is read, so an authentic earlier-revision statement cannot slip past it by
also failing some later check.

## Duration grammar (core spec §7.3)

`duration::parse_iso8601_duration_nanos` parses `checkpoint_cadence` and `witness_grace_period`
identically: time components only (`P[n]DT[n]H[n]M[n]S`); `Y`, or `M` in the date part, rejected
as a named `ProhibitedDurationComponent`, never approximated; fractional seconds accepted to at
most nine digits, with a tenth digit or beyond rejected outright — **never truncated or
rounded**, since truncating `PT0.0000000009S` to zero is exactly the kind of
implementation-dependent divergence the component restriction exists to prevent. Separately,
`governance::resolve` rejects a manifest whose `checkpoint_cadence` normalizes to zero
nanoseconds (core spec §7.3: "`checkpoint_cadence` MUST be greater than zero") — a zero cadence
would make every gap, however large, satisfy a maximum-gap obligation of zero, which is not a
cadence at all. That check lives in `governance`, not `duration`, because it is specific to
`checkpoint_cadence`'s semantics and does not apply to `witness_grace_period`, which the same
parser also produces.

## Why this duplicates `ahl-mirror`'s `manifest` module

Core spec §3.3 requires a witness to be independent of the log operator; `ahl-mirror` is
commonly operated as, or alongside, that operator's infrastructure. Deriving a witness's trust
decisions from a mirror's already-computed governance state would make the witness's
independence conditional on trusting the mirror's computation of it — precisely the kind of
single point of failure witnessing exists to remove. This crate's `governance` module therefore
re-derives governance from raw entry bytes independently, verifying every producer signature and
predecessor link itself.

The cost is duplication: `ahl-witness`'s `governance`, `checkpoint`, `duration`, `config` and
`metadata` modules implement the same algorithms as `ahl-mirror`'s `manifest`, `checkpoint`,
`duration`, `config` and `metadata` modules, adapted for a witness's own needs (notably,
`governance::GovernanceState` retains `witness_grace_period`, which a mirror has no use for and
discards). **Recommendation**: this verification core — governance-chain resolution, checkpoint
blob assembly and signature verification, duration parsing, and the ATL adaptor metadata
constant — would be better shared as a small library crate (e.g. `ahl-adaptor-atl-verify`) that
both `ahl-mirror` and `ahl-witness` depend on, so the two components structurally cannot drift
apart on what a valid checkpoint or a valid governance chain is. This report does not implement
that extraction; it would require restructuring `ahl-mirror`, which is out of this crate's
scope.

## Feeding the witness

`witness::witness_checkpoint` is deliberately free of network I/O: it takes a candidate
checkpoint and the entries needed to verify it as plain arguments, so it is fully unit-testable
without a mock server. Getting those bytes from a log or mirror is the caller's job. The HTTP
`POST /v1/logs/{log_id}/witness` endpoint accepts them inline (base64-encoded entries and an
optional raw checkpoint blob) for direct submission — from a script, a CI job, or an operator's
own polling loop against their `ahl-mirror` instance's `/v1/range` and `/v1/checkpoints`
endpoints. This crate does not ship a bundled poller; wiring one up against a specific mirror's
authentication and retry policy is a deployment concern.

## Publication interface

| route | method | purpose |
| --- | --- | --- |
| `/health` | GET | liveness |
| `/v1/witness-key` | GET | this witness's id, key id and public key |
| `/v1/logs/{log_id}/witness` | POST | submit a checkpoint (+ entries) to be witnessed |
| `/v1/logs/{log_id}/checkpoint` | GET | the latest cosigned checkpoint for this log |
| `/v1/logs/{log_id}/checkpoints` | GET | the complete cosigned history for this log |
| `/v1/logs/{log_id}/refusals` | GET | every refusal evidence published for this log |
| `/v1/logs/{log_id}/freshness` | GET | staleness of the latest cosigned checkpoint |

A verifier can therefore obtain a witnessed checkpoint, or evidence that the log equivocated,
without going through the log operator at all (core spec §3.3's verifier algorithm: "accept a
checkpoint C only with a valid witness cosignature").

## Specification questions raised, and how core spec settled them

Three rounds of review against this crate produced core-spec clarifications; recording both what
was asked and how it was resolved, rather than only the final state, since the earlier rounds'
reasoning is what a future spec reader needs to know a question was ever open.

- **Bootstrap refusal carries no evidence — confirmed correct.** Adaptor profile §11.2's schema
  requires both a `retained` and an `offered` checkpoint; the very first checkpoint ever
  witnessed for a log has no `retained` predecessor, so if its claimed root does not recompute
  from its own entries there is nothing to pair it with in a two-checkpoint refusal. This crate
  reports that case as `WitnessError::CheckpointRootMismatch` — an authentication-level failure,
  not `WitnessOutcome::Refused` — rather than fabricating a placeholder `retained` field. Core
  spec §3.3 now states this directly: "Before a first checkpoint is retained there is no partner
  to pair with, so a refusal at bootstrap carries no two-checkpoint evidence and MUST be reported
  as such rather than fabricating a partner."
- **Equivocation lockout is permanent — confirmed correct.** Whether a witness could resume
  cosigning once fresh checkpoints extended safely past a recorded floor was open; this crate
  took the conservative reading (permanent, no defined recovery) on the grounds that a witness
  cannot determine, from checkpoint metadata alone, which conflicting branch a later checkpoint
  honestly extends. Core spec §3.3 now states it directly: "A later well-formed checkpoint does
  not clear an equivocation record, and a witness MUST NOT resume cosigning a log past its
  recorded floor."
- **Grace resolves like cadence — confirmed correct.** `witness_grace_period` is taken from the
  manifest version governing the checkpoint in question, never the newest version, exactly as
  `checkpoint_cadence` is (core spec §7.3; §3.3 restates it for grace specifically). This crate
  already stored cadence and grace alongside each cosigned checkpoint at cosign time for this
  reason (`store::RetainedCheckpoint`); no change was needed once the rule was made explicit.
- **Comparing only against the newest retained member misses equivocation — a real defect,
  fixed.** The first implementation round's `witness_checkpoint` classified an offered checkpoint
  purely against the single latest retained one. Given cosigned sizes 1, 2, 3, a *conflicting*
  offered checkpoint at size 2 was classified as a size regression against size 3 — the
  equivocation at size 2 went undetected. Core spec §3.3 names the fix normatively: "An offered
  checkpoint whose `(log_id, tree_size)` matches one already cosigned with a different
  `root_hash` is equivocation, whatever its size relative to the newest retained member." See
  "Equivocation ends the series" above for the fix, and
  `witness::tests::equivocation_is_detected_against_full_history_not_only_the_newest_member` for
  the regression test.
- **Per-call locking does not make a multi-step decision atomic — a real defect, fixed.** Two
  concurrent submissions extending the same retained checkpoint to different roots at the same
  new size could both read the pre-write state, both pass classification, and both be cosigned.
  Core spec §3.3 now requires the whole transition to be serialized and atomic per log, with an
  equivocation record persisted atomically with its justifying refusal. See "Serialization and
  atomicity" above for the fix and its concurrency test.
- **The refusal reason taxonomy was under-specified and partly unverifiable — redesigned.**
  Adaptor profile §11.2's `inconsistent` reason covered both size regressions and failed
  extensions, neither of which a verifier could distinguish or recheck from two root hashes
  alone. Core spec §3.3 now requires every reason to be independently checkable and forbids
  emitting one whose verification procedure is undefined. See "Refusal reason taxonomy" above for
  the three-reason replacement this crate defines and proposes back to the profile.
- **`extension-failed` evidence was not bound to the pair it claimed to be about — a real
  defect, fixed.** `verify_refusal_claim` checked only that `offered.tree_size >
  retained.tree_size`, then delegated to a replay function that verified the carried proof
  using the proof's *own* `from_size`/`to_size` — never checked against `retained.tree_size`/
  `offered.tree_size`. A structurally valid, genuinely failing proof for some unrelated pair of
  sizes therefore validated a refusal about a completely different pair. Fixed by requiring
  `consistency::verify_extension_failure` to check `evidence.from_size == retained.tree_size`
  and `evidence.to_size == offered.tree_size` before replaying anything, returning a clean
  `false` (not an error) on mismatch — see "Refusal reason taxonomy" above and
  `consistency::tests::a_proof_for_an_unrelated_pair_of_sizes_does_not_validate_this_refusal`.
  This round also fixed the wording: `extension-failed` means precisely "the carried purported
  extension proof fails verification," never "no valid extension exists" — a witness showing
  one proof fails never establishes that every proof would.

## Quality bar

Same harness as `ahl-mirror`: `clippy.toml`, `rustfmt.toml`, the `[lints]` block, GitHub Actions
CI (`fmt`, `clippy -D warnings`, `test`, `doc -D warnings`, `cargo llvm-cov --fail-under-lines
90`, MSRV 1.92.0 check) and weekly `cargo audit`. No `unwrap`/`expect`/`panic!` outside
`#[cfg(test)]`. Deterministic tests only — no real clocks, no real network.

## License

Apache-2.0.
