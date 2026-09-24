# Retained BigCode excerpt

This directory retains the dependency-free `benchmark_name_to_filter_reason`
and `find_substrings` functions from
`bigcode-project/bigcode-dataset/decontamination/find_substrings.py` at commit
`bebec929edd826f19b5fa3538f22d18d5b50da4b` (Git blob
`446313901df4de049a3cfc473152f438b542c799`). The repository's
`decontamination/README.md` states that this exact-substring script was used to
remove files matching code-generation benchmark samples from SantaCoder and
StarCoder training data.

The excerpt is Apache-2.0 licensed. It is invoked through
`src/builder_adapter.py`; no third-party package, network access, benchmark
execution, or model execution is required. The artifact does not claim that
the small retained bridge workload reproduces the full BigCode production
pipeline.
