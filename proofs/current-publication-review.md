# Bounded publication interface and evidence (2026-10-14)

This review does not introduce a new propagation or release-gating algorithm.
The complete controller-manifest gate was already implemented in the prepared
candidate. Missing members, including members with no exports, cannot pass
sealing. Local emission is a different sealed-snapshot primitive; it is not a
composed release. Policy labels and complete membership are trusted inputs,
not facts discovered by the ledger.

## Source-fragment correspondence

The inspected primary versions are [Thoth, USENIX Security 2016](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_elnikety.pdf)
(19 physical PDF pages, including cover; article pp. 637–654 and Appendix A)
and [Data Capsule, arXiv:1909.00077v1](https://arxiv.org/pdf/1909.00077)
(13 pages). Both were read through their references/appendix, not just abstracts.
This is not a full-text certification of the other 83 bibliography entries.

Thoth §2 and §§3.3–3.4 use conduit policies, policy-set taints, checked
declassification conditions and write-transaction closure. Section 2 footnote 1
explicitly says the full language supports provenance policies, omitted there
for space. Data Capsule §3.1's fourth phase gates declassification by policy
satisfaction and analyst role; §§5.3–5.4 infer transformation effects and residual
policies. These mechanisms already cover policy propagation and output gating.

ContainmentLedger's result is bounded to the declared exact textual fragment and its
equality-only interface. It does not prove that either prior mechanism cannot
implement the fragment, or establish a production advantage over them.

| Scope | Local transfer | Cross-shard identity | Authorized pair repair |
| --- | --- | --- | --- |
| B = 1 | Derivation and content equality | Exact canonical code N(c) | Direct B edge remains |
| O = 2 | Registered occurrence and derivation | None; occurrence namespaces remain disjoint | Direct O edge remains |
| M = 4 | Derivation and pair equality | Exact (N(c), i), with exact intent i | Only direct M edge is suppressed; equal after-pair obligations remain |

N normalizes CRLF/CR to LF and removes trailing spaces/tabs per line; it is not
a semantic compiler equivalence. Complete registries, even unused roots, enter
local replay. Non-exported intermediate keys enter the B/M quotient. A global
joined replay namespaces occurrences while identifying B/M equality keys.
The same information therefore admits ordinary repeated-edge fixed-point
closure: it must not be disadvantaged by removing intermediate keys or members.

The paper's equality-only proposition corresponds to argument D1 and
`checker.verify(..., summary=True)` / `merge.compose`. Contextual characterization
corresponds to E1: fixed finite interface K, every key seedable/queryable,
C = Reach(S), and E* restricted to K minus C. The information argument E2 is
for that fully general interface, not a universal compression bound on complete
inputs or every workload. Tests in `tests/context.py` are bounded checks of those
arguments, not unbounded theorem mechanization. These specific characterizations
are not presented in the two inspected articles; coverage by adaptations or other
prior work remains unresolved.

## Publication argument to actual code

Argument I's release consequence requires trusted complete membership, fixed
policies, disjoint occurrence namespaces, correct replay, uncompromised role
keys, HMAC unforgeability and SHA-256 collision resistance (including pinned
capsule encodings). Within implementation bounds:

1. `release.publish_files` parses both files with the bounded rejecting reader.
   `admit_release` requires an exact list of policy/ledger/capsule records.
2. `Consumer.admit` owns copies, checks the whole-capsule pin, verifies both role
   tags and policy/log digests, replays, compares the full summary and exact
   output order, and requires the pinned sequence exactly.
3. `seal` requires every manifest member exactly once, including empty-export
   members, and composes in manifest order. D1 then supplies the joined masks.
4. `consume` refuses any nonzero selected output mask, reconstructs selected
   exports again and checks order. `publish` uses the unchanged atomic
   create-if-absent publisher. No caller-supplied verdict enters this boundary.

Admission is bounded by 20,000 members, 64 MiB aggregate canonical admitted
records, 20,000 outputs, 40,000 quotient keys, 240,000 arcs and 128 MiB key text,
in addition to local replay/parser limits. Those limits are not evidence of
production scale. Revision pinning does not advance persistent freshness.
Publication and freshness remain separate, non-transactional operations.

## Current evidence, separate from history

The actual repair is default-reproduction coverage: previously CI separately
ran the release suites, while `reproduce.py --checks` and its saved success
record omitted them. A controlled new coverage regression fails against that
default. All 23 existing portable semantic tests passed in that red run.
The new publication workflow runs the existing suites plus the coverage anchor
(24 tests) and retains five small serialized contexts, with a raw-record
all-pairs Boolean reference and a same-information fixed-point consumer.

Current receipt: `results/owned-publication-20261014-current/receipt.json`.
Ten actual two-file pipelines produce six read-back archives and four blocked
refusals. Expected target masks are respectively (0,0), (1,1), (0,0), (0,0),
(4,4): clean, late B without exports, O-only equality, different-intent M,
and an independently registered after-pair M following repair. Both methods
receive identical JSON files, keys and obligations. Exact archive bytes tie.
Raw emitted bytes are retained losslessly as `.zip.hex` text to preserve the
packet's no-nested-archive rule; no code or archive content is executed/extracted.

The whole current receipt reports 4.250461599993287 wall seconds and 4.109375
process-CPU seconds on the recorded Windows/Python host. It includes unit
suites, fixture setup/issuance, input writes, reference checks, both file
pipelines and intermediate output recording. Per-method costs include both
file reads, parsing, full authenticated admission, composition, selected
reconstruction, publication/refusal, readback and raw-byte recording. Final
receipt serialization/verification, typesetting, old campaigns, persistent
freshness and POSIX process-death checks are outside that timer. Single ordered
observations establish regression costs, not performance or ranking gains.

`results/owned-publication-package-20261014-current.json` records 38 AST-parsed research
sources and static package/input checks, not full execution of those sources.
Its owned receipt controls accept the original and reject inflated test count,
source drift and a missing raw input. Retained historical result files are
unchanged. The earlier 80-execution comparison uses a different input wrapper
and remains separate. The initial new-driver diagnostic-serialization failure
is also retained; its incomplete receipt is not a successful current result.

The default Linux supervisor now includes this source-bound publication stage
and verifies its raw bundle. Its full current POSIX execution is not established by the recorded Windows activity. No Windows run is substituted for procfs/subreaping,
POSIX process-death, freshness, power-loss or production-builder evidence.

## Remaining scientific and venue obligations

Natural repeated text is observed, but policy scopes/labels and the transformation
contexts are assigned. The BigCode bridge retains one exact substring function,
not a full production builder. Operational policy authority, independent natural
cases, builder/storage integration and downstream decision benefit are not
established by these controls. The fixed-point baseline ties; 52 historical
inclusion-minimal-versus-minimum cut gaps remain explicit. The finite arguments
are handwritten, not machine checked.
