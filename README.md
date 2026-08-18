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

`witness::witness_checkpoint` is the single entry point implementing all four steps. Given a
candidate checkpoint, the complete ordered entry byte sequence `[0, tree_size)` (needed to
resolve governance — see below), and the current time, it returns either
`WitnessOutcome::Cosigned` or `WitnessOutcome::Refused`, or a `WitnessError` for a candidate
that never authenticated at all (see "Authentication failures are not refusal evidence" in the
module's doc comment for why that distinction matters and is drawn deliberately).

Consistency is decided by `consistency::check` without trusting any externally-computed proof:
given leaf hashes covering `[0, offered.tree_size)`, it classifies the pair as `Consistent` (a
genuine append-only extension, or an idempotent republish at equal size and root),
`Equivocation` (equal size with a different root), `Inconsistent` (a size regression, or a
consistency proof that fails to verify), or `ProofUnavailable` (a proof could not even be
generated from the supplied material).

## Equivocation ends the series (core spec §7.3)

Core spec §7.3 states this normatively and in terms that apply directly to a witness: "Two
authenticated members sharing a `tree_size` with differing `root_hash` values are equivocation,
not a tie … From the lowest `tree_size` at which it occurs, the series is no longer canonical …
Detecting equivocation and then continuing to serve one branch is a conformance violation."

`witness_checkpoint` therefore does more than refuse the one conflicting candidate: the first
time it observes equal-`tree_size`, different-`root_hash` checkpoints for a log, it records an
**equivocation floor** (`Store::record_equivocation`) and every later call for that log —
however validly signed, however genuine an extension it might otherwise be — is refused without
running ordinary consistency checking, so no later checkpoint can ever be cosigned in a way that
would make either conflicting branch look canonical again. The read side,
`witness::published_checkpoint`, is the counterpart: once a log has an equivocation floor, it
reports `PublishedCheckpoint::Equivocated` (surfaced over HTTP as `409 Conflict` on both
`GET /v1/logs/{log_id}/checkpoint` and `.../freshness`) instead of the latest retained row,
however validly that row was itself cosigned before the divergence was found. The refusal
evidence published for the triggering pair (`GET /v1/logs/{log_id}/refusals`) still carries both
conflicting checkpoints — nothing about equivocation handling weakens that guarantee.

## Why enumerated governance, not a shortcut

Adaptor profile §10.6 states plainly that this profile provides **no typed-subset proofs**:
there is no capability that proves "these are all the manifest and key entries in this range"
without carrying the full range. A witness resolving governance from anything less than the
complete `[0, tree_size)` entry sequence could miss a key rotation or a manifest change and
silently trust a checkpoint signed by a retired key. `governance::resolve` therefore always
requires the full ordered entry sequence, exactly as `ahl-mirror`'s governance resolution does.

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

## Specification ambiguities encountered

- **Refusal evidence assumes a prior retained checkpoint.** Adaptor profile §11.2's schema
  requires both a `retained` and an `offered` checkpoint. The very first checkpoint ever
  witnessed for a log has no `retained` predecessor; if its claimed root does not recompute from
  its own entries, there is nothing to pair it with in a two-checkpoint refusal. This crate
  reports that case as `WitnessError::CheckpointRootMismatch` (an authentication-level failure)
  rather than manufacturing refusal evidence with a placeholder `retained` field. Neither core
  spec §3.3 nor the adaptor profile names this bootstrap case, and it remains unnamed even after
  the §7.3 "Equivocation ends the series" addition, which is written in terms of two *already
  authenticated* members — a single unauthenticatable candidate with no predecessor falls
  outside it.
- **"Missing consistency proof" is under-specified for a witness that builds its own proofs.**
  Adaptor profile §11.2 writes as though a consistency proof is handed to the witness and can be
  simply absent. This crate instead recomputes consistency itself from supplied entries (see
  "Why enumerated governance, not a shortcut" — the same material serves both purposes), so
  `missing-consistency-proof` is reachable only when a proof cannot even be *generated* from
  what was supplied. The distinction between this and `inconsistent` is drawn by this crate, not
  dictated unambiguously by the profile text.
- **Freshness governance snapshot.** Core spec §3.3 item 4 and adaptor profile §11.3 both say
  staleness is judged "against the cadence of the manifest version governing the range in
  question, not against the current version's value," but neither spells out which checkpoint's
  *governing version* that means for a witness that has not seen a new checkpoint in a long
  time. This crate uses the manifest version that governed the checkpoint at the moment it was
  cosigned (stored alongside it), which is the interpretation consistent with `ahl-mirror`'s
  reading of the same clause for its own gap-free-frontier computation.
- **What "withhold any witness assertion" requires of *future*, unrelated checkpoints is a
  reading choice.** Core spec §7.3 is explicit that nothing *at or beyond* the equivocation
  floor may ground an assertion, but does not spell out whether a witness may resume cosigning
  once fresh, unambiguous checkpoints extend safely past the point of divergence. This crate
  takes the conservative reading — equivocation is terminal for a log, permanently, once
  recorded — on the grounds that a witness has no way to determine, from checkpoint metadata
  alone, which of the two conflicting branches (if either) a later checkpoint is honestly
  extending; resuming trust could silently make one branch look canonical again, which is
  exactly what §7.3 forbids. A future revision could define a recovery procedure (e.g. a new
  manifest version acknowledging the fork); none exists today.

## Quality bar

Same harness as `ahl-mirror`: `clippy.toml`, `rustfmt.toml`, the `[lints]` block, GitHub Actions
CI (`fmt`, `clippy -D warnings`, `test`, `doc -D warnings`, `cargo llvm-cov --fail-under-lines
90`, MSRV 1.92.0 check) and weekly `cargo audit`. No `unwrap`/`expect`/`panic!` outside
`#[cfg(test)]`. Deterministic tests only — no real clocks, no real network.

## License

Apache-2.0.
