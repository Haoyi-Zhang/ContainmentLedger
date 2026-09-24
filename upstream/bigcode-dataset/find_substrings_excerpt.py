"""Verbatim function excerpt from BigCode's exact-substring decontaminator.

Upstream: bigcode-project/bigcode-dataset
Commit: bebec929edd826f19b5fa3538f22d18d5b50da4b
Path: decontamination/find_substrings.py
Blob: 446313901df4de049a3cfc473152f438b542c799
License: Apache-2.0 (see LICENSE)

Only the two dependency-free functions used by the experiment are retained.
Their bodies are copied without semantic changes. The surrounding BigCode
program depends on Hugging Face datasets and is not executed by this artifact.
"""


def benchmark_name_to_filter_reason(benchmark_name: str):
    return f"{benchmark_name}_match"


def find_substrings(data, filter_out, return_matched=False):
    """
    filter_out: Dict[str, List[str]] mapping from benchmark name to list of strings that need to be
    filtered-out.
    Return True, None if the file should be included in the dataset.
    Otherwise return False and some metadata about the file excluded
    """
    content = data['content'].lower()
    # For each substring, try to find it in the file (case insensitive)
    for benchmark, substrings in filter_out.items():
        for substring in substrings:
            if substring.lower() in content:
                if return_matched:
                    return False, benchmark_name_to_filter_reason(benchmark), substring
                else:
                    return False, benchmark_name_to_filter_reason(benchmark)

    # Return True, None if none of the substrings was found
    if return_matched:
        return True, None, None
    else:
        return True, None
