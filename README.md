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
checker and compares the local policy, ledger, summary, and outputs. Composition
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

## Retained inputs, observed equality, and builder bridge

`data/public/` contains 24 exact files from six public releases: CPython 3.13.5,
Go 1.23.2, Ruby 3.3.8, Perl 5.40.1, npm CLI 10.9.2, and pip 25.1.1. The retained
set totals 268,614 bytes and 8,215 physical lines. Four files are fixed per
release. Selection, upstream locations, byte counts, and license information
are recorded in `data/selection.json`; notices are under `licenses/`.

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

Requirements: Python 3.10 or newer on a POSIX system with the standard
`resource` module. No third-party Python package, network access, GPU, compiler,
service, credential, or private data is required.

Run from this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python reproduce.py --checks
PYTHONDONTWRITEBYTECODE=1 python reproduce.py --scale chain-distinct
PYTHONDONTWRITEBYTECODE=1 python reproduce.py --scale alias-copy
PYTHONDONTWRITEBYTECODE=1 python reproduce.py --scale many-roots
PYTHONDONTWRITEBYTECODE=1 python reproduce.py --verify
```

`--checks` runs the pilot, 480-case campaign, mutation campaign, finite closure
and cut oracles, contextual characterization, natural-equality workload,
retained builder-function bridge, authenticated capsule/publication suite,
persistent freshness suite, parser/representation boundaries, and both
command-line validators. The three scaling commands run 12 fresh-process
observations each at 512, 2,048, 8,192, and 20,000 logical vertices. `--verify`
checks and collates the saved part reports; it does not rerun experiments.

Each part uses one worker. A child has a 30-second wall limit and an outer part
a 35-second limit. The runner uses private process groups, kills the group on
timeout or interruption, and sets a 3 GiB address-space ceiling where supported.
These are execution guards, not tight worst-case resource proofs.

## Retained evidence

| Evidence | Result and scope |
|---|---|
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
| `results/reproduction.json` | authoritative final sequential-part timing, CPU, and peak-child-RSS accounting |

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
PYTHONDONTWRITEBYTECODE=1 python src/ledger.py \
  data/example-policy.json data/example-ledger.json
PYTHONDONTWRITEBYTECODE=1 python src/checker.py \
  data/example-policy.json data/example-ledger.json
PYTHONDONTWRITEBYTECODE=1 python src/emitter.py \
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
