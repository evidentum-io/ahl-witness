# ahl-witness fuzz targets

Five libFuzzer targets, covering every place the crate reads bytes it did not produce.

| target | what it drives |
| --- | --- |
| `witness_request` | the body of `POST /v1/logs/{log_id}/witness` — the crate's only request body — through the handler's own extraction and then `witness::witness_checkpoint`, including the I-D §7.1 transition exception, which a seed reaches by carrying a rotating manifest and a checkpoint signed by the outgoing log key |
| `checkpoint` | a submitted checkpoint object through the §6.3 time grammar, the §6.1 blob assembly and the §6.5 signature check |
| `governance` | arbitrary bytes as an anchored entry through `governance::resolve`, offered both as entry 0 and after the real genesis, plus the §7.3 duration grammar |
| `refusal` | published refusal evidence and cosigned checkpoints through the rechecks a verifier runs on them, including the replay of a carried consistency proof |
| `config` | the JSON deployment file the binary reads at startup, and a single log anchor within it |

The store-backed target opens a fresh in-memory `SQLite` store per input and primes it with one
cosigned checkpoint, so the consistency, equivocation and extension-failure branches are
reachable and the run still depends on the input alone. Every target handles each `Result`,
indexes nothing and asserts nothing: a panic reported by one is a defect in the library, never
in the harness.

Run them on nightly (libFuzzer needs it), passing the committed seeds as a second corpus
directory:

```sh
cargo +nightly fuzz build
mkdir -p fuzz/corpus/witness_request fuzz/corpus/checkpoint fuzz/corpus/governance \
         fuzz/corpus/refusal fuzz/corpus/config
cargo +nightly fuzz run witness_request fuzz/corpus/witness_request fuzz/seeds/witness_request -- -max_total_time=60
cargo +nightly fuzz run checkpoint      fuzz/corpus/checkpoint      fuzz/seeds/checkpoint      -- -max_total_time=60
cargo +nightly fuzz run governance      fuzz/corpus/governance      fuzz/seeds/governance      -- -max_total_time=60
cargo +nightly fuzz run refusal         fuzz/corpus/refusal         fuzz/seeds/refusal         -- -max_total_time=60
cargo +nightly fuzz run config          fuzz/corpus/config          fuzz/seeds/config          -- -max_total_time=60
```

## Seeds

The crate under test ships no committed test data — its fixtures are built in code, inside
`#[cfg(test)]` modules — so the seeds are built the same way rather than transcribed, by
`examples/gen_seeds.rs`, from two fixed key seeds and one genesis manifest:

```sh
cargo +nightly run --example gen_seeds
```

That example is not a fuzz target; `cargo fuzz build` builds the crate's `[[bin]]` targets
only. It writes valid and deliberately invalid documents per target: cosigning and refusing
witness requests, a checkpoint whose time does not round-trip and one whose `tree_size` is
`u64::MAX`, the genesis manifest and a `key` statement, three durations, real
extension-failure and equivocation evidence produced by running the state machine, and a
deployment configuration.

`corpus/` and `artifacts/` are working directories and are not committed.
