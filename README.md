# Context-complete containment ledgers

This standalone repository accompanies **Context-Complete Containment Ledgers
for Repackaged Code Corpora**. It implements and checks a bounded defensive
contract: restrictions already assigned to corpus material must survive the
declared transformations and later equality-only composition that the contract
covers. It is not a poisoning detector, malware analyzer, model-training
system, or proof of an unobserved physical acquisition history.

## Contract and threat boundary

A trusted policy snapshot registers exact source text and three label scopes:

- **B (content scoped):** follows canonical textual equality;
- **O (occurrence scoped):** follows one declared occurrence and its
  derivation, but not an unrelated equal source; and
- **M (code–intent-pair scoped):** follows one exact code/intent association
  and can be suppressed only by a catalog-authorized direct pair repair.

A producer declares imports, copies, line-ending normalization, code-point
extraction, literal replacement, authorized pair repair, collection, filtering,
mixing, pair-key deduplication, and archive recomposition. Two separately
implemented replay paths reconstruct exports from the registry, rebuild
scope-specific closure, and compare exact outputs and claims. The emitter
publishes only when the separately implemented checker reports a zero mask on every
retained export.

Acceptance is conditional on the registry, policy snapshot, canonicalizer,
repair catalog, and frozen algebra. It excludes inconsistent byte substitution,
omitted declared edges, scope conversion, and stale local-clean decisions
within that boundary. It does not establish registry completeness, correct
policy assignment, semantic program equivalence, or downstream model safety.

## Authenticated composition and publication profile

`src/capsule.py` implements a standard-library, shared-key HMAC-SHA256 profile.
A capsule binds:

- contract identifier, shard identifier, policy epoch, and sequence number;
- SHA-256 digests of the exact policy, ledger, and quotient summary;
- output order and names; and
- the complete equality-only composition summary.

A policy-authority key authenticates the policy binding and a separate checker
key authenticates the complete capsule body. Bound verification reruns the
checker and compares the local policy and ledger digests, full summary, and outputs.
Exact-object binding is computational: it assumes HMAC-SHA256 unforgeability
and SHA-256 collision resistance on canonical policy and ledger objects.
The complete authenticated summary is compared structurally. Composition
rejects duplicate capsule identities and multiple revisions for one shard.

`src/freshness.py` adds an authenticated local state file. Under a POSIX file
lock it verifies a bound capsule with epoch-scoped role keys, requires a strict
per-shard sequence advance, and atomically replaces an HMAC-authenticated state
record after synchronizing the candidate. State survives process restart and an
epoch/key change requires an explicit old/new transition. This is local replay
protection, not whole-state rollback detection, public signatures,
non-repudiation, transparency, distributed consensus, or key distribution.
Pre-replacement process death can leave an unreferenced private temporary file.
Test keys in the repository are public fixtures and must not be reused.

`src/emitter.py` validates first, creates an exclusive same-directory temporary
ZIP through an opened non-symlink directory, synchronizes the file, commits by
an atomic create-if-absent hard link, synchronizes the directory, removes the
temporary name, and synchronizes again. The campaign checks concurrent writers,
preexisting and symlink destinations, a symlink parent, and six process-death
checkpoints. These observations apply to process death on the evaluated POSIX
filesystem; they do not establish arbitrary power-loss or network-filesystem
durability.

### Which operation replays which evidence

`capsule.issue(policy, ledger, ...)` performs local checker replay before issuing
a capsule. `capsule.verify_bound(policy, ledger, capsule, ...)` authenticates,
checks local policy/ledger bindings, and reruns the checker. In contrast,
`capsule.verify(capsule, ...)` authenticates the capsule and validates its bounded
schema, summary, digests and supplied expectations; it has no original ledger
to replay. `capsule.compose(...)` calls `verify` on each capsule, rejects
duplicate identities and duplicate shards, and composes authenticated
summaries without replaying the original ledgers. Thus this path trusts the
checker role to have honestly replayed before authenticating its assertion;
HMAC key possession alone is not proof that replay occurred.

`freshness.accept_bound(...)` is separate: under its state lock it calls
`verify_bound`, then persists the strictly advanced per-shard sequence floor.
Calling `verify` or `compose` does not advance that file. The deployment suite
counts real checker calls for issue/verify/compose/verify_bound/accept_bound as
1/0/0/1/1, while preserving all actual return values.

The untrusted byte readers for policy/ledger JSON and authenticated freshness
state enforce lexical depth/atom limits and reject duplicate keys and non-finite
constants. The state file additionally has its own 4 MiB ceiling. Capsule APIs
accept already-decoded Python objects: they cannot recover a duplicate key that
an external permissive decoder already discarded. Fixed input-selection and
result JSON are trusted local artifact metadata, not hardened ingress APIs.

## Retained inputs, observed equality, and builder bridge

`data/public/` contains 24 exact files from six public releases: CPython 3.13.5,
Go 1.23.2, Ruby 3.3.8, Perl 5.40.1, npm CLI 10.9.2, and pip 25.1.1. The retained
set totals 268,614 bytes and 8,191 physical LF lines. Four files are fixed per
release. Selection, upstream locations, byte counts, and license information
are recorded in `data/selection.json`; notices are under `licenses/`.
All 24 files end in LF. A trailing empty split segment is not a physical line;
the earlier `count("\n") + 1` convention counted 24 such segments. No upstream
source bytes were changed.

The files are treated only as UTF-8 text. They are never imported, compiled,
executed, used to train a model, or classified as actually poisoned. Generated
labels are controlled fixture facts, not allegations about any project.

In addition to the 20 fixed scenario families, `src/corpus_adapter.py` discovers
canonical nonblank lines of at least eight scalar values that occur in distinct
retained files. For every discovered file pair, it builds an exact
`import → extract → rewrite → collect → repack` ledger in which the naturally
repeated line is a non-exported intermediate and the exported descendants are
different. The retained workload has 127 line classes and 216 file-pair
contexts, including 13 cross-project pairs. Thresholds 12, 20, and 40 are also
reported. The workload is not a clone benchmark or a prevalence sample.

`src/builder_adapter.py` directly invokes the retained dependency-free
`find_substrings` decision from BigCode's public exact-substring decontaminator,
pinned by repository, commit, path, and Git blob under `upstream/bigcode-dataset/`.
For each retained source file, a deterministic natural line is treated as a
generated filter fact; one exact MIT-licensed HumanEval example supplies a
benchmark-shaped filter. The root matches, a one-character declared rewrite
causes the endpoint to pass the same upstream scanner, and the ledger still
blocks the descendant. Twenty-four absent-probe controls pass both scanner and
replay. This is a real function-level integration, not a reproduction of the
full BigCode builder, benchmark collection, or operational policy authority.

## Complete reproduction

Requirements: Python 3.10 or newer on **Linux/POSIX with procfs**, `resource`,
`wait4`, and child-subreaper support. No third-party Python package, network,
GPU, model API, service, credential, or private data is required. The `-S`
option skips unrelated site initialization; it does not disable any check.

Run these five commands from this directory, sequentially:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python -S reproduce.py --checks
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python -S reproduce.py --scale chain-distinct
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python -S reproduce.py --scale alias-copy
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python -S reproduce.py --scale many-roots
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 python -S reproduce.py --verify
```

`--checks` first runs the mandatory **hardening part**: eight small upstream
matching/nonmatching queries through both maintained loading paths, fixture-key
JSON boundary checks, seven supervisor probes, the exact package/source audit,
and the existing additional oracle/mutation/transform/microbenchmark gate. It
then runs the **checks part**: pilot, assigned-policy and mutation campaigns,
finite closure/cut/context oracles, natural equality, the retained builder
bridge, capsule/publication and persistent-freshness tests, parser/emitter
boundaries, both CLI validators, and the emitter example. There is no unmetered
scientific prelude. In particular, all two warmups and eleven repetitions for
each of the supplementary microbenchmark's three shapes and eight sizes are
inside the hardening worker's CPU, wall and RSS observations.

The other three parts run the original scaling shapes, each with three fresh
processes at each of 512, 2,048, 8,192 and 20,000 vertices. `--verify` checks the
five saved part records, their **current source/input SHA-256 bindings**, the
hashes of generated evidence files, command statuses, and scientific
invariants. It does not rerun experiments. Those checks remain active under
`python -O`; an old PASS from different source or changed evidence is rejected.
The source inventory is measured afresh (29 maintained Python files in this
packet), not copied from an earlier audit. Result JSON records the source and
input snapshot used for each measurement. The retained measurements precede
the summary-comparison change; changed source requires a fresh supervised run
before its results can satisfy the current-source verification command.

One supervised coordinator runs at a time, with affinity limited to at most
four available CPUs. The explicitly bounded publication/freshness races each
launch eight small contenders, not eight unbounded campaign workers. The
hardening, core-check and each scaling part have 170, 90 and 60 second wall
budgets. Each launched command has a wall deadline no larger than its remaining
part budget (160 seconds in hardening, 55 elsewhere), with a reserved three
seconds for cleanup. A worker and its descendants inherit a 3 GiB per-process
address-space ceiling and a CPU ceiling. Aggregate descendant RSS is sampled
every 10 ms and killed above 3 GiB; this sampling is not a proof of an
instantaneous memory bound. Address-space refusal is tested with a much smaller
64 MiB fixture limit.

The Linux subreaper waits for orphaned descendants; process groups and tracked
process descendants are killed on timeout/interruption, nonzero-worker cleanup,
or unexpected surviving descendants. Every command retains stdout/stderr,
exit status, termination reason, waited CPU, peak-process RSS, sampled group
RSS and cleanup status. A catchable failed or interrupted part is recorded as failed
before returning nonzero; an abruptly killed coordinator leaves a non-passing
`running` record, never an old success; it cannot validate the old success record.

`results/reproduction.json` distinguishes worker/descendant CPU, coordinator
CPU, five-part wall time, and saved-result verification overhead. The total
covers the supervised scientific work, including the additional scaling gate;
it excludes earlier development, document compilation, archive packaging,
inter-command idle time and interpreter startup before entering the part.
Peak process RSS is not summed or misreported as simultaneous group memory.

## Retained evidence

| Evidence | Result and scope |
|---|---|
| `results/upstream-regression.json` | 8 pure matching/nonmatching queries through the shared complete fixed-path loader |
| `results/freshness-json.json` | 3 valid fixture-key controls, 14 syntax/authentication boundary rejections, 2 persisted malformed states left unchanged |
| `results/runner-guards.json` | 7 controlled supervisor cases; five expected worker failures retain real metrics and clean descendants |
| `results/reviewer-hardening.json` | 14,400 small-model cases, 12 listed abstract mutants, 120 retained-line rewrites checked by both replayers, and 264 supplementary quotient-oracle timing repetitions |
| `results/package-audit.json` | exact delivery whitelist, 29 maintained Python files, fixed upstream excerpt and physical LF accounting |
| `results/campaign.json` | 6 projects, 24 files, 20 families, 480 assigned-policy cases: 336 blocked and 144 clean |
| `results/mutations.json` | 288 malformed or false-claim records rejected by both replay implementations |
| `results/composition.json` | 2,457 merge contexts and 4,962 output masks; complete summaries equal joined replay throughout |
| `results/composition-baselines.json` | cached local decisions leave 846 false-clean outputs; seed-to-output equality leaves 1,626; endpoint-only aliasing leaves 492 |
| `results/natural-duplicates.json` | 127 observed line classes and 216 file-pair contexts; complete and authenticated composition agree with joined replay in all 216, while endpoint-only caching misses all 216 clean-side outputs |
| `results/builder-bridge.json` | original retained BigCode decision code rejects 25 roots; all 25 rewritten endpoints pass the same scanner yet remain lineage-blocked; 24 clean controls pass both checks |
| `results/deployment.json` | 23 capsule/freshness/path cases rejected; one winner in an 8-process publication race; six process-death checkpoints satisfy the stated pre/post-commit condition |
| `results/freshness.json` | authenticated state survives restart, rejects 7 replay/tamper/epoch cases, accepts one of 8 racing advances, and preserves a complete old-or-new state at four death checkpoints |
| `results/finite-closure.json` | 327,680 exactly enumerated graph/label instances, zero oracle disagreements |
| `results/finite-cuts.json` | 15,625 grouped-edge graphs; 11,456 cut certificates, 4,169 infeasibility certificates, and 2,059 rejected certificate mutations |
| `results/context.json` | 262,144 abstract local/context combinations and 64 concrete rewrite probes, zero disagreements |
| `results/boundaries.json` | 144 clean archives emitted/read; all 336 blocked archives refused; 20 parser/text/export boundary checks |
| `results/diagnoses.json` | 288 inclusion-minimal outcomes and 192 uncuttable-path outcomes across the 480 valid cases |
| `results/scaling-*.json` / `.csv` | three deterministic shapes, four sizes through 20,000 vertices, three fresh processes per size |
| `results/reproduction.json` | five-part source-bound timing, worker/coordinator CPU, peak-process RSS and sampled group-RSS accounting |

The same-information fixed-point comparator ties scoped replay on every valid
fixture. That is expected: the contribution is the scope contract,
reconstructible evidence, authenticated composition boundary, and diagnostic
semantics—not a new reachability algorithm or a claimed speedup over an upstream
system.

## Source organization

- `src/ledger.py` is the producer/replayer using a monotone bitset worklist.
- `src/checker.py` independently implements replay with three graph traversals
  and a different equality-star construction; it imports no producer module.
- `src/merge.py` constructs and composes scope-specific quotient graphs.
- `src/capsule.py` validates, issues, authenticates, binds, and composes
  shared-key summary capsules.
- `src/freshness.py` persists authenticated per-shard sequence state and enforces
  explicit epoch/key transitions under an interprocess lock.
- `src/corpus_adapter.py` constructs the natural repeated-line workload from
  exact retained source coordinates.
- `src/builder_adapter.py` invokes the retained BigCode filter decision and
  translates its assigned result into an exact rewrite/repackage ledger.
- `src/emitter.py` performs checker-gated create-if-absent ZIP publication.
- `src/diagnose.py`, `src/cuts.py`, and `src/cutcheck.py` reconstruct the audit
  graph, generate inclusion-minimal separators or infeasibility witnesses, and
  validate certificates without importing the optimizer.
- `proofs/arguments.md` states the general handwritten arguments and
  assumptions. Finite programs can find bounded counterexamples; they are not a
  proof assistant.
- `claim_evidence_ledger.csv` maps every material claim to arguments, code,
  inputs, raw results, maturity, and limitations.
- `external_resources.csv` records retained inputs, licenses, publisher assets,
  and scholarly sources used in the design comparison.

The validators share a format, mathematical specification, runtime, and
program authorship. They are implementation-diverse checks, not independent
external review. Exact minimum-cardinality diagnosis is capped at 18 action
groups; deterministic inclusion-minimal diagnosis is capped at 64.

## Minimal example

```sh
PYTHONDONTWRITEBYTECODE=1 python -S src/ledger.py \
  data/example-policy.json data/example-ledger.json
PYTHONDONTWRITEBYTECODE=1 python -S src/checker.py \
  data/example-policy.json data/example-ledger.json
PYTHONDONTWRITEBYTECODE=1 python -S src/emitter.py \
  data/example-policy.json data/example-ledger.json checked.zip
```

The emitter never overwrites an existing destination. ZIP member names are
checked in the declared POSIX-style namespace; the emitter is not a universal
secure extractor for every downstream filesystem.

## Limitations

The labels and repair authorities are generated, and the 24 files are a compact
convenience sample. Literal replacement and code-point extraction are exact text
operations, not industrial semantic refactoring. Composition is argued and
tested only for declared equality-only contexts over a known finite interface.
Full text keys are retained, so summaries provide neither confidentiality nor a
general compression guarantee.

The artifact does not discover unknown contamination, prove registry truth,
provide public-key attestation, production key management, whole-state rollback
detection, or distributed availability. It invokes one original builder
decision function but does not reproduce or deploy the complete BigCode
pipeline, use a real policy authority, measure model behavior, or demonstrate
superiority over prior systems. Process-death tests are not power-loss tests.
The parser, filesystem, and denial-of-service campaigns are bounded, not
exhaustive. All performance numbers are observations from saved fresh
processes, not service-level guarantees or worst-case resource bounds.

The additional-evidence ledger explicitly marks unavailable inherited ancillary
records. A prior reviewer-audit report, separate reviewer-hardening proof note,
and online 55-record reference-validation result were not supplied and are not
reconstructed. The retained `proofs/arguments.md`, current regenerated tests, and
paper's offline citation-coverage audit must not be confused with those missing
records.
