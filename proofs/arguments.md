# Scoped containment: definitions and arguments

These are handwritten mathematical arguments about a finite declared model.
They are not a machine-checked development or a proof about arbitrary software.
The implementation and finite tests are separate evidence. In particular, the
resource caps are implementation guards; the asymptotic constructions below
refer to the uncapped family of finite models unless a bound is specified.

## A. Values, policy and replay

A value is a pair `(c,i)` of valid Unicode scalar strings, called code and
intent. They are data, not executable programs or natural-language truths.
Canonicalization N replaces CRLF and remaining CR with LF, then removes ASCII
space and tab at each line end. Code equality means `N(c)=N(c')`; pair equality
means code equality and `i=i'`. No Unicode normalization, semantic equivalence,
parsing or intent equivalence is inferred.

A trusted policy snapshot contains finitely many roots with exact values and
initial masks in the powerset of `{B,O,M}`, and a finite authorization catalog.
A catalog item binds the exact triple `(code,before-intent,after-intent)`.
The interpretation of B as content scoped and M as pair scoped is itself a
trusted policy assumption. O is scoped to a declared source occurrence, not to
all copies of equal text or to an independently observed physical origin.

Each unit has one earlier parent unit, except an import whose parent is a
registered root. Import and copy preserve the exact pair. Extraction takes a
nonnegative, ordered code-point substring. Normalization applies N to code.
Literal replacement substitutes a declared nonempty string everywhere in the
parent code, subject to the implementation's expansion guard. These three
operations preserve intent. An authorized repair requires exact agreement
with a catalog item's code and before-intent; it preserves code and emits the
catalog's after-intent. The checker compares the declared output pair against
this deterministic result. This is not a theorem that any code transformation
preserves execution behavior, or that any repair produces a correct intent.

Collections are ordered lists of unique member names and unit references.
Repacking changes names deterministically without changing references.
Filtering selects ordered, distinct positions. Mixing creates a distinct
numeric namespace for each input collection. Deduplication retains the first
representative of each code/intent key. A final export must equal the complete
selected collection, including order, references, code and intent. Dropping an
unselected member is allowed; changing the ancestry of a retained unit is not.

Let V contain every registered root and declared unit. In particular, a
registered root is not dropped just because a producer did not mention it.
There is one directed derivation edge from each parent to its child. The edge
transmits every label, except that an authorized repair does not transmit M.
For every code-equality class, add a bidirectional spanning star transmitting
only B. For every pair-equality class, add such a star transmitting only M.
There are no equality edges transmitting O. The unit-order graph is acyclic,
but these equality edges deliberately introduce cycles.

For a label l, let E_l be the edges whose mask contains l, S_l the roots seeded
with l, and T the retained unit vertices. Define

    L_l = the least X such that S_l ⊆ X and E_l(X) ⊆ X.

A unit's mask is the union of the labels for which it belongs to L_l. Exact
claimed masks are checked for every unit, not only the final exports.
A structurally valid corpus is blocked if some retained unit has a nonzero
mask. A validator can report a well-formed blocked corpus without treating it
as clean; the emitter requires every retained mask to be zero.

## B. Path characterization and conditional replay soundness

**Proposition B1 (path characterization).** For every label l and vertex v,
`v ∈ L_l` if and only if an E_l-path leads from some vertex of S_l to v. A
zero-length path is allowed.

**Proof.** Let R be the vertices reachable from S_l. R contains S_l and is
closed under E_l, so leastness gives L_l ⊆ R. Conversely, every closed set
containing S_l contains the successive vertices of every finite source path,
by induction on path length. Therefore R ⊆ L_l. Finiteness ensures that
repeatedly adding successors terminates, but the set equality itself follows
from the two containments. Cycles do not require a topological ordering. ∎

**Proposition B2 (conditional replay and emission).** Assume that the policy
snapshot, scope meanings, catalog and checker execution are trusted. If the
checker accepts all structural and label assertions, every declared unit is
the exact result of its declared finite derivation and its mask is exactly
that of Proposition B1. If the emitter succeeds, the emitted code/intent
members are a fresh reconstruction of the selected zero-label units.

**Proof.** Order the unit records by their required earlier-parent relation.
For an import, the exact registered value is the only accepted value. For a
non-import, the induction hypothesis fixes the parent. Schema validation and
the operation's deterministic definition fix the child, and an exact value
comparison rules out a different reported pair. In the repair case, catalog
membership and the exact before/code binding are checked before evaluating
the after-intent. Thus every value is determined by an accepted derivation.

Induct next over the collection records. Collection references must exist;
each collection operator has a deterministic ordered result. Unique valid
names and the final full-list comparison exclude missing, reordered,
additional or substituted exports relative to that declaration. This does
not forbid an explicitly declared filter; it forbids an undeclared mismatch.

For each label, the checker explores E_l from all S_l and therefore computes
exactly L_l by B1. Comparing every claimed mask makes any falsely clean
annotation reject. The producer instead uses repeated masked union; each
addition is justified by a source or an already reached predecessor, and
termination leaves a closed set. B1 gives equality of the two mathematical
answers, not correctness of either program merely because they agree.

The emitter requests exports reconstructed by the separate checker, rejects any
nonzero retained label before opening its destination, and writes their
UTF-8 encodings into separate code/ and intent/ namespaces. With correct
standard-library I/O and no hostile concurrent modification, successful
completion writes precisely these values. It writes and synchronizes an
exclusive same-directory temporary file, then publishes it with an atomic
create-if-absent hard link. Before the link no destination exists; after the
link the destination names a complete synchronized ZIP. Exception cleanup
removes only the temporary name and never unlinks a committed destination.
This is an implementation contract, not a theorem about power-loss
persistence, filesystem attackers or secure ZIP extraction by other programs. ∎

**Corollary B3 (non-erasure in scope).** A label on any trusted source reaches
all retained descendants along paths permitted for that label, including
permitted equality steps. Neither renaming nor final-state omission of a
marker clears such a path. An authorized repair can suppress its own incoming
M edge, but another pair-equality path still imposes M. Equality alone cannot
transfer O, because no O equality edge exists.

This is a conditional preservation result, not discovery of bad content.
A false trusted label, unregistered source, invalid authorization decision,
missing physical observation or dishonest consumer lies outside B2. A clean
mask has no semantics beyond absence of these declared policy obligations.

## C. What the observation does not determine

**Proposition C1 (physical-history boundary).** A verifier receiving only the
policy, declared ledger and final text cannot always distinguish lawful
reconstruction from an unobserved disallowed acquisition that supplies the
same verifier input.

**Proof.** Register a B-labelled value `alpha` and an unlabelled different
value `beta`, with distinct canonical code. An observed ledger imports beta
and retains it. One physical history actually does that. Another unobserved
history obtains alpha, performs a literal change to beta, and supplies the
same observed ledger. Both have the same policy, ledger and final text;
therefore every deterministic verifier produces the same answer on them.
For a randomized verifier the answer distributions are identical. A verifier
that permits the first input cannot reject only the second physical history
without some additional trusted observation. The example uses benign symbol
strings, not a poisoning exploit. ∎

The result does not say a trusted rebuilding verifier is ineffective. Fresh
emission realizes the declared beta import rather than certifying the
producer's hidden past. It also does not say signed process attestations are
useless: authenticated capture can add observations absent from this model.

**Proposition C2 (sealing before irrevocable decisions).** If an interface may
later reveal arbitrary new trusted labelled roots, a currently zero-labelled
output cannot in general receive an irrevocable clean decision before that
interface is sealed.

**Proof.** Consider two extensions of the same observed prefix. The first
adds no roots. The second adds a B-labelled root with the canonical code of
an intermediate unit that reaches the output by B-transmitting derivations.
The first extension can remain clean and the second is blocked by B1. Before
the extension is known, the observations are identical. A decision invariant
under both extensions cannot be both exact and irrevocably clean. ∎

This is an exactness boundary under arbitrary additions, not a claim about
latency, a lower bound for every possible streaming interface, or a proof that
all roots must always be held in memory. A restricted import interface, a
sealed snapshot, or a protocol allowing revocation changes the premise.

## D. Equality-only composition

For each locally checked shard and each l in `{B,M}`, contract its l-equality
classes to full text keys. Keep its projected derivation edges, source keys
and retained-output keys. Equality-star edges become self edges and may be
omitted. For O, keep the locally calculated output labels. This is the
implemented summary; it is not a transitive-closure matrix or a minimal
encoding. All keys, including those of non-exported intermediates and unused
registered roots, remain available.

Composition takes disjoint occurrence namespaces and unchanged local policy
snapshots. It identifies equal full keys across shards and unions projected
edges and seeds. It does not introduce a new transformation between internal
occurrences in different shards. It computes B and M reachability on these
unions and joins them with the preserved local O output labels.

**Proposition D1 (composition equivalence).** Under this equality-only
composition contract, the output masks obtained by composing valid local
summaries equal those obtained by replaying the fully namespaced union.

**Proof.** Fix l=B or l=M. Any full graph path maps to a quotient path: a
within-key equality step maps to stuttering, and a derivation step maps to
its retained projected edge. Root and output projections preserve the ends.
Thus full reachability implies quotient reachability.

Conversely, each projected derivation edge has a concrete original witness.
Successive projected edges might use different representatives of the same
key. Since every original equality class is connected in both directions,
and equal keys from different shards acquire equality links in the combined
graph, the end of one witness can reach the start of the next without changing
the key. Inserting these equality paths lifts the quotient path to the full
graph. Its first and last representatives can similarly be connected to the
required source and output. The two reachability relations agree.

O has no equality edges. No cross-shard derivation is introduced, so an O path
to a shard's output starts and remains in that shard. Its local O result is
therefore unchanged. Combining the three per-label equivalences proves the
mask statement. The choice of spanning-star center does not matter to either
containment. ∎

This theorem authenticates neither a remote summary nor its producer. The
implementation assumes summaries are trusted outputs of local checking.
A changed source policy, revoked repair, newly declared cross-shard operation,
or overlapping occurrence identity requires revalidation under an expanded
contract, not an appeal to D1.

**Counterexample D2 (final-only alias checking).** Let one shard have an
unlabelled value x, a rewrite x→y, and a second rewrite y→z, exporting z.
A second shard contributes a B-labelled registered value y. Local status and
final-code comparisons see no equality between y and z. Nevertheless the
combined graph has a path from the newly labelled y key through the second
rewrite to z. Retaining all intermediate keys detects it. A one-pass procedure
that checks aliases only at final outputs can miss this path.

## E. Exactly observable contextual information

The following statement concerns one B-scoped quotient graph, not all policy
semantics at once. Fix a finite interface K whose keys may all be added as
seeds and queried as output ports by a context. Let H=(K,E,S) be a local graph
with initial seeds S. Contexts may add arbitrary directed edges on K and
arbitrary additional seeds. The observation is the set of labelled keys after
closure. Let C=Reach_E(S). Let R be reflexive transitive reachability in E,
restricted to pairs with both ends outside C.

Two local graphs over the same K are context equivalent if their observations
are equal for every such context. An external graph with extra vertices can
also be handled by identifying its interface K; paths outside K can be
compressed to interface transitions before the argument below.

**Proposition E1 (contextual characterization).** Two graphs over the fixed,
fully queryable interface are context equivalent if and only if their C sets
and their restricted R relations agree.

**Proof, sufficiency.** Replace a local graph by seeds C and directed relation
R on K\C. Every R edge abbreviates an actual local path, and every vertex of C
is reached from S. Consequently any path in the replacement, together with
context edges, can be lifted to an original local/context path.

For the other direction, take an original local/context path. Its initial
local segment from S lies in C. Whenever the path reaches a vertex in C, that
vertex can be treated as a seed and the preceding prefix omitted. A local
edge cannot leave C: if it did, its endpoint would be in Reach_E(S)=C.
Therefore, after the path's last visit to C, each maximal local segment has
both endpoints outside C, and is represented by an edge of R. Context edges
are unchanged. Replacing these segments gives a path in the replacement.
A path starting at an added seed and never visiting C is represented by the
same replacement of its local segments. This proves equal observations for
every context. Graphs with identical C,R
have identical replacements and hence identical contextual observations.

**Proof, necessity.** If the two C sets differ, the empty context and an output
port in their symmetric difference distinguish them. Otherwise let their
common C be fixed, but suppose (x,y) belongs to one restricted R and not the
other. Both x and y lie outside C. Add just a seed at x and query y. The first
graph reaches y; the second does not, because neither its original seeds nor
x can reach y. Thus this context distinguishes the graphs. ∎

The restriction outside C is essential. An edge into an already labelled
region can be observationally redundant: seeds label that region regardless
of the edge. It would be false to claim that all raw edges or the complete
unrestricted reachability relation are always recoverable from observations.
Likewise, a smaller set of output ports, restrictions on future seeds, or
secret/unnameable keys weakens the necessity direction. The implementation
retains a sufficient quotient graph; it does not compute the canonical C,R
representation or claim optimal summary compression.

**Proposition E2 (worst-case summary information).** For a fixed interface of
2b distinct keys and arbitrary equality contexts, an exact deterministic
summary must distinguish 2^(b²) locally clean worlds. In particular, a uniform
fixed-length encoding needs at least b² bits. A variable-length encoding has
worst-case length at least b² bits as well when counting all shorter binary
strings without a separate free information channel.

**Proof.** Partition the keys into x_1,...,x_b and y_1,...,y_b. For every subset
A of the b² ordered pairs (x_i,y_j), create a graph with exactly those edges
and no seeds. There are no edges out of a y key and no edges into an x key.
Thus adding a seed at x_i labels y_j exactly when (i,j)∈A. If two subsets differ,
the corresponding seed/query context distinguishes them, so exact summaries
cannot encode them identically. There are 2^(b²) different subsets. At most
2^q distinct fixed-length q-bit summaries exist. For variable-length strings
of length strictly below b², the total is 2^(b²)-1, still insufficient. The
counting argument gives the claimed worst-case information requirement.

These graphs are expressible using the frozen text operations. Register all
2b keys as unlabelled roots with a common intent. Import each x_i. For every
(i,j)∈A, literally replace the entire code x_i with y_j in a child of that
import. Use no initial labels and an empty local export list. All duplicate
y_j values collapse to the same interface key, and there are no unintended
internal aliases because the x and y strings are distinct. A context adds a
B-labelled x_i root and a clean import/export of y_j. Equality transfers the
context seed to the relevant local import and transfers the corresponding
rewrite result to the queried output exactly when that edge was declared.
This realizes every distinguishing context without executing code. ∎

The quadratic information bound concerns interface size, not complete ledger
size: the construction already has quadratically many rewrites. It is not a
quadratic lower bound in full input size or a contradiction of linear-size
quotient storage measured against that full input.

The construction uses at most 2b roots, b imports and b² rewrites, or
b²+3b logical vertices. At b=128 this is 16,768, below the 20,000-vertex
implementation guard. This bound is on the mathematical count, not a claim
that all 2^(16,384) instances were run. The finite test realizes all 16 relations
for b=2 and checks all four probes per relation through producer, separate
checker and composition. Its separate three-key enumeration checks 512 local
graph/seed worlds against 512 contexts each. None of these finite checks is a
mechanized proof of E1 or E2, or evidence that the information argument is a
new result in graph summarization.

## F. Diagnostic separators and witnesses

A diagnostic graph has finite vertices, directed edges, source set S and
target set T. Every edge is either uncuttable or belongs to an action group.
Deleting a group deletes every edge bearing that action. Import edges and
scope-equality edges are uncuttable in the corpus adapter. The action map for
eligible non-import records is a trusted audit input; unmapped operations
also remain uncuttable. It is not supplied by an adversary as evidence that a
security policy permits deleting history.

A set C of groups is a separator if G−C has no S-to-T path. It is
inclusion-minimal when no proper subset is a separator. A minimum-cardinality
separator has the fewest groups among all separators. These notions differ.

For a claimed separator C, a certificate supplies a vertex set Z containing
S, disjoint from T and closed under all remaining edges. For each a∈C it also
supplies a source-to-target edge-index path in G−(C\{a}). For infeasibility it
supplies a source-to-target path using only uncuttable edges. Edge indices,
continuity, group conditions and endpoints are checked against a separately
reconstructed canonical graph, not a producer-provided graph digest.

**Proposition F1 (certificate soundness).** Acceptance of a separator
certificate proves feasibility and inclusion minimality for that graph and
action map. Acceptance of an infeasibility certificate proves no action-group
separator exists.

**Proof.** If Z contains S and is closed under remaining edges, induction along
any path in G−C keeps every reached vertex in Z. Since Z is disjoint from T,
there is no source-to-target path. For each selected action a, the supplied
path shows that C\{a} is not a separator. Any proper subset D⊂C omits at least
one such a, and deleting fewer groups cannot destroy that same path.
Therefore D is not a separator; C is inclusion-minimal. The checker need not
establish that Z is exactly the reachable set: closure, inclusion of S and
exclusion of T are sufficient.

For infeasibility, removing any subset of action groups leaves the uncuttable
path intact. A source that is also a target yields a valid zero-edge witness.
Thus the argument covers this boundary as well. ∎

**Proposition F2 (one-pass minimization).** Start by removing all groups.
If an uncuttable path remains, infeasibility is proved. Otherwise consider
groups once in a fixed order, restoring a group whenever separation persists.
The final set is inclusion-minimal.

**Proof.** Feasibility is invariant because a restoration is committed only
when no source-to-target path results. Suppose a group is tested and retained.
Restoring it at that point gives a path. All later committed restorations add
edges rather than remove them, so that path will still exist if the retained
group is restored in the final graph. Hence every final retained group has a
necessity witness. F1 then establishes inclusion minimality. ∎

**Proposition F3 (unbounded cardinality gap for this order).** There is a
family in which the fixed restoration order returns k groups although a
one-group separator exists.

**Proof.** Use k internally disjoint two-edge paths from s to t. Every first
edge has group a, while the second edge of path j has its own group z_j.
Process a before all z_j. With all groups removed, restoring a leaves every
path cut by its z_j, so a is restored. Restoring any z_j now completes its
path, so all k such groups are retained. Yet removing a alone cuts all paths.
For k≥1 the ratio is k; it grows without bound in the uncapped family. ∎

This does not say that all inclusion-minimal separators are large: the
one-group separator is also inclusion-minimal. It also does not say that
ordinary single-edge minimum cut is hard. The distinction is repeated action
groups and the chosen algorithm's non-optimal selection order.

**Proposition F4 (hitting-set reduction).** Minimum-cardinality grouped
separation includes minimum hitting set by a size-preserving reduction.

**Proof.** Let X be a finite universe and F a finite family of subsets of X.
For each nonempty A∈F, create one s-to-t path with private intermediate
vertices and one edge of group x for each x∈A, in any fixed order. Paths share
only s and t. A group set C disconnects s from t exactly when C intersects
every A∈F, because each path is broken precisely by such an intersection.
The numbers of selected groups and selected universe elements are equal.
For an empty A, insert an uncuttable s-to-t path, making both the hitting-set
instance and the separator instance infeasible. For an empty family, both
optima are zero.

The nonempty construction is also expressible by text derivations: use one
B-labelled start key, a different common terminal key, globally distinct
internal keys, and a sequence of whole-string rewrites along each path.
Assign each rewrite its corresponding group. Equal start and terminal values
act only as the shared endpoints; globally distinct intermediate keys prevent
unintended crossings between paths. Imports and equalities are uncuttable.
A clean registered terminal import can provide the retained output, which
receives B exactly along surviving paths. An empty-set obligation may be
represented by an ungrouped rewrite path. ∎

This reduction explains why the artifact only enumerates exact group subsets
for at most 18 actions and uses witness-certified inclusion minimality for up
to 64. It is not a new hardness theorem about ordinary edge cuts, nor does it
prove that the chosen heuristic is a useful optimizer on production data.

## G. Diagnosis is not remediation

Deleting a diagnostic edge changes a counterfactual explanation graph. It does
not reconstruct a different source value, issue a new repair authorization,
revoke a trusted label, or change the bytes of an already retained output.
The emission rule always uses the original replay and closure, not the graph
with a diagnostic cut applied. Therefore F1 never overrides B2.

A malformed record such as a missing root, impossible byte output, duplicate
JSON key or unauthorized repair does not establish the graph required by F1.
The validator reports that failed obligation. For a structurally valid record
with a false label annotation, a diagnostic graph can still be reconstructed:
only the annotation equality check is bypassed, never schemas, source binding,
transformation replay, output matching, group eligibility or label domains.
This distinction is explicit in the separate audit adapter.

## H. Implementation obligations and finite evidence

The two policy/ledger byte readers and the authenticated freshness-state
decoder bound byte size, lexical depth and token-like syntax atoms before
decoding, reject repeated object keys and non-finite constants,
and reject booleans used as integers. The text checks reject invalid Unicode
scalar encodings and oversized values. Replay imposes node, edge, record,
member-obligation, aggregate text and expanded-export byte bounds. These are
finite representational checks; they are not a proof of a worst-case
aggregate Python memory bound, host security, or constant-memory streaming.

The certificate checker bounds graph and witness obligations, checks
individual witness paths against actual edge records and avoids importing the
optimizer. The general handwritten proofs do not validate the implementation
line by line. Separately implemented traversals, exact tiny Boolean oracles,
mutations, stress shapes and clean extraction are intended to reveal
counterexamples, not to substitute for machine-checked refinement.

The evidence bindings and actual counts are in `claim_evidence_ledger.csv`.
No proposition claims semantic cleanliness, safety of a learned model,
malicious-author attribution, universal contamination detection, reliable
upstream labels or recording of the producer's physical history. The
relationship to existing information-flow, policy-compliance and provenance
systems remains a central scientific comparison, not a solved novelty gate.

## I. Authenticated capsules and create-if-absent publication

The deployment profile adds two conditional guarantees to the logical replay
contract. They do not strengthen the truth of the registry or policy, and they
do not turn a diagnostic into permission to change an output.

**Proposition I1 (computational capsule binding).** Assume
the policy-authority and checker HMAC keys are uncompromised, HMAC-SHA256 is
unforgeable for the adversary, SHA-256 is collision resistant on the canonical
policy and ledger domains, canonical JSON encoding is deterministic, and
the verifier retains an authentic expected epoch and per-shard sequence floor.
If bound verification accepts a capsule with a locally supplied policy and
ledger, then the accepted contract identifier, shard, epoch, sequence, policy
digest, ledger digest, summary digest, output names, and complete quotient
summary are the values authenticated by the two roles and recomputed from that
policy and ledger, except with the corresponding MAC-forgery or hash-collision
failure probability. This is computational object binding, not unconditional
injectivity of the digest.

**Argument.** The authority tag covers a domain-separated tuple containing the
contract, epoch and policy digest. The checker tag covers a second
domain-separated canonical encoding of every capsule field except the checker
tag itself, including the authority tag. Verification rejects a noncanonical
schema, recomputes both tags, recomputes the summary digest, and enforces the
caller-held epoch, shard and sequence constraints. Bound verification then
recomputes the policy and ledger digests, reruns the separately implemented checker,
compares its validated summary structurally with the authenticated summary,
and requires the exact output order. Changing a covered authenticated field
requires a MAC forgery. Substituting a different canonical policy or ledger
under unchanged authenticated digests requires a SHA-256 collision. The union
of those bad events bounds failure; summary equality needs no additional
digest-to-object inference. A compromised key, rolled-back
freshness state, or false trusted policy is outside the conclusion. The result
is shared-key integrity, not public verifiability, non-repudiation,
transparency, key distribution or consensus on rollback state. ∎

**API and role boundary.** `issue` and `verify_bound` perform local checker
replay. `verify` authenticates and validates a bounded capsule but does not
receive or replay its original ledger. `compose` calls `verify`, rejects
repeated capsule identities and repeated shards, then composes summaries.
Summary-only composition therefore trusts the checker role to have correctly
replayed before authenticating its assertion; possession of a checker key is
not itself evidence of correct replay. `accept_bound` separately calls
`verify_bound` and persists a strictly advanced local sequence floor. The
functional call-count regression checks 1/0/0/1/1 local checker invocations
for these five paths; it does not replace the mathematical composition argument.

The state decoder rejects malformed wire syntax before canonicalizing for
HMAC verification. The fixture tests insert a duplicate generation and a NaN
that a last-key-wins decoder would discard, while keeping the valid canonical
body and tag. These are parser-boundary cases, not MAC forgeries or rollback
attacks. Valid canonical/whitespace encodings remain accepted; rejected
persisted inputs are not rewritten. Already-decoded capsule objects and fixed
local metadata files have no claimed lexical provenance from an external JSON
parser.

**Proposition I2 (process-death publication boundary).** Assume an opened,
trusted POSIX directory in which creation of a hard-link name is atomic and a
same-directory temporary inode remains the inode linked at commit. If replay
has returned clean exports and the emitter follows its stated sequence, then
(i) before the hard-link operation succeeds, the destination name has not been
created by that invocation; (ii) a successful hard link creates the destination
only if it was absent and points it at an already closed and file-synchronized
complete ZIP; and (iii) failure after that link does not cause the emitter to
remove the committed destination.

**Argument.** All checking and reconstruction precede opening the destination
directory. The emitter creates only an exclusive temporary name, writes and
closes the ZIP, changes its mode and synchronizes its file descriptor. It then
uses `link(2)` with source and destination relative to the already opened
directory. Atomic create-if-absent link semantics yield either one new name for
the complete temporary inode or failure with an existing destination unchanged.
The exception path removes only the temporary name; it deliberately never
unlinks a destination after commit. Directory synchronization and later
temporary-name cleanup are attempted after the linearization point. Thus a
process death before the link can leave an unlinked temporary file but no
new destination, whereas a process death after the link leaves a complete
published inode and may also leave the temporary name. This argument is not a
claim about power loss, storage-controller behavior, every file system, network
file systems, hostile mutation by the directory owner, or secure extraction by
downstream tools. Those properties require separate evidence. ∎

The deployment tests authenticate natural-workload capsules, mutate covered
fields and caller context, race eight publishers, exercise symlink and
preexisting paths, and force process death at six checkpoints. Those executions
instantiate the stated profile on the evaluated host; they are not a proof of
the cryptographic assumption or universal file-system durability.

## J. Persistent local freshness and an operational filter bridge

**Proposition J1 (local restart-persistent sequence advance).** Assume the
state HMAC key and epoch-scoped capsule keys are uncompromised; cooperating
verifiers use the same regular lock file; `flock` serializes those cooperating
processes; and same-directory replacement is atomic. If `accept_bound` returns
for shard `s` at sequence `q`, then every later cooperating invocation that
reads the resulting authentic state in the same epoch requires a sequence
strictly greater than `q`. Concurrent invocations for the same next sequence
have at most one successful return.

**Argument.** Every invocation acquires the exclusive lock before reading the
state and holds it through verification and replacement. The record's HMAC is
checked before its accepted-sequence map is used. Capsule verification binds
the shard and requires at least the stored value plus one. The candidate state
sets the shard to the accepted sequence and is fully written and synchronized
before atomic replacement. Therefore a later lock holder sees either the prior
complete state (if replacement did not occur) or the new complete authentic
state (if it did); in the latter case the same sequence fails the strict floor.
A process dying after replacement can consume a sequence before any later
publication, which is fail closed. A privileged actor that restores an older
complete state file, lock bypass by a noncooperating process, key compromise,
file-system power loss, or distributed agreement is outside this conclusion.
An explicit epoch transition is permitted only for the caller-supplied exact
old/new pair; its new sequence namespace is authenticated under the new role
keys. This is not an ordering proof over arbitrary epoch names or a public key
revocation protocol. ∎

**Observation J2 (endpoint filtering and derivation containment are
non-equivalent).** Let an exact-substring filter reject a root because it
contains string `p`. If a declared rewrite changes an occurrence of `p` so the
final text no longer contains `p`, rerunning that same endpoint filter can
accept even though a content-scoped restriction assigned to the root still
reaches the descendant through the declared rewrite edge.

**Argument.** Exact substring membership is a predicate of the current byte
string. Replacing one character in the only selected occurrence makes that
predicate false. The ledger's content label instead follows the declared
root-to-child derivation and therefore remains in the least fixed point unless
a separately authorized rule removes it. The retained BigCode function and an
separate four-case oracle instantiate the membership predicate; 25 bounded
rewrite cases instantiate the distinction. This observation does not imply
that BigCode's complete production pipeline relies only on a final scan, that
its policy should use the generated fixture labels, or that any retained
upstream file is actually contaminated. ∎
