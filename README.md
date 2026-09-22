# ProvTrail

Find JavaScript and TypeScript code that matches known vulnerable implementations,
including copied or modified code. ProvTrail compares functions against recorded
vulnerable/patched source pairs and produces a local HTML report with upstream
advisories, code comparisons, and evidence for each finding.

## Quick Start

### 1. Install

Requires **Python 3.11+** and **Git**. CPU execution is supported.
Choose **one** of the following installation methods, then continue to step 2.

#### Option A: pipx — standalone command

With [pipx installed](https://pipx.pypa.io/latest/how-to/install-pipx.html), install
directly from GitHub. pipx manages its own environment; no activation is needed.

```sh
pipx install "git+https://github.com/ElsonNg/sc4079-fyp.git"
pipx ensurepath
```

Reopen your terminal, then run `provtrail --help` from any directory.

#### Option B: virtual environment — local checkout

Clone the repository and create an environment:

```sh
git clone https://github.com/ElsonNg/sc4079-fyp.git
cd sc4079-fyp
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on macOS/Linux, or
`.\.venv\Scripts\Activate.ps1` in PowerShell, then install:

```sh
python -m pip install .
```

Use `python -m pip install -e .` instead if you plan to edit the tool.

#### Option C: wheel — existing package file

In an activated virtual environment, install your wheel file:

```sh
python -m pip install ./provtrail-0.1.0-py3-none-any.whl
```

### 2. Prepare the reference corpus

**The package does not bundle a populated corpus.** For a new installation, set
`GITHUB_TOKEN` in your environment or in a `.env` file in the working directory:

```dotenv
GITHUB_TOKEN=your_github_token
```

Build the corpus once:

```sh
provtrail corpus build
provtrail corpus stats
```

Corpus building requires network access and can take time. Confirm that
`corpus stats` reports entries before continuing.

Already have a populated corpus? Skip the build and use
`--db-path /path/to/corpus.db` with `corpus index`, `scan`, and `corpus stats`. Missing indexes are
built on the first scan. See [data locations](#data-and-configuration) to reuse
existing indexes too.

### 3. Set up the local embedding model

ProvTrail uses **Qwen/Qwen3-Embedding-0.6B** by default. The install includes
PyTorch and Sentence Transformers; the following command downloads the model
weights on first use, runs the model locally, and builds both search indexes:

```sh
provtrail corpus index --embed-model qwen3-embedding-0.6b --device cpu
```

Wait for indexing to finish before scanning. This setup works with every install
method above and requires no separate model server or Ollama installation.
Weights are cached for later runs. To choose their location, set `HF_HOME` before
running the command; see the [Hugging Face cache settings](https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables#hf_home).
The model cache is separate from `PROVTRAIL_DATA_DIR`, which stores the corpus and indexes.

To use CPU for subsequent scans too, set this in each terminal session:

```sh
export PROVTRAIL_EMBEDDING_DEVICE=cpu  # macOS / Linux
```

```powershell
$env:PROVTRAIL_EMBEDDING_DEVICE = "cpu"  # PowerShell
```

Without this setting, PyTorch/Sentence Transformers selects an available device.
Use the same embedding model for indexing and scanning; `scan` also accepts
`--embed-model qwen3-embedding-0.6b`, which is already the default.

### 4. Scan a project

```sh
provtrail scan /path/to/project
```

Open `/path/to/project/.provtrail/latest-scan.html` in your browser. The same
directory contains `latest-scan.json` for automation. Repeat the scan to reuse
unchanged function results.

For a small example, see the [paired vulnerable/patched demo](examples/paired_demo/README.md).

## Documentation

### Reports and output flags

```sh
provtrail scan /path/to/project --output scan.json --sarif-output findings.sarif --ai-output findings.txt
provtrail report scan.json --verbose
```

| Flag | Command | Purpose |
|---|---|---|
| `--output PATH` | `scan` | Save scan JSON; the HTML defaults to the same path with an `.html` extension. |
| `--html-output PATH` | `scan` | Choose a separate HTML report path. |
| `--sarif-output PATH` | `scan`, `report` | Export actionable findings as SARIF 2.1.0. |
| `--ai-output PATH` | `scan`, `report` | Export compact text for review or an AI assistant; use `-` for stdout. |
| `--json` | `scan`, `report` | Print JSON instead of the terminal summary. |
| `--verbose` | `report` | Show advisory, version, score, and provenance details. |
| `--include-informational` | `report` | Include informational results in verbose or JSON output. |

`report` accepts either a saved JSON file or the scanned project directory, and
does not rerun detection. `--ai-output -` cannot be combined with `--json`.
SARIF and compact text include automatic vulnerability findings and manual reviews.

**Example SARIF result** (`findings.sarif`, one illustrative entry from
`runs[0].results`; the full file includes tool metadata and fingerprints):

```json
{
  "ruleId": "provtrail/manual-review",
  "level": "note",
  "message": {
    "text": "parseQuery: The vulnerable and patched edits are too similar to distinguish confidently."
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {"uri": "src/query.js", "uriBaseId": "%SRCROOT%"},
      "region": {"startLine": 12, "endLine": 28}
    }
  }]
}
```

**Example AI output** (`findings.txt`, the same illustrative finding):

```text
ProvTrail AI v1
root: /path/to/project
src/
  query.js:12-28 REVIEW confidence=high reason=The vulnerable and patched edits are too similar to distinguish confidently.
total=1 vuln=0 review=1
```

`REVIEW` requests manual inspection; `VULN` marks an automatic vulnerability finding.
Advisory IDs and package applicability appear when available. This is a text export
for an AI assistant to read; generating it does not call an LLM.

Scan/report exit code **1** means automatic vulnerability or manual-review findings
need attention; **0** means neither was reported. A clean result is limited by the
reference corpus and is not a guarantee that the project is vulnerability-free.

### Data and configuration

Data defaults to `%LOCALAPPDATA%\ProvTrail` on Windows and
`${XDG_DATA_HOME:-~/.local/share}/provtrail` on macOS/Linux. Set
`PROVTRAIL_DATA_DIR` to select a corpus/index directory. To reuse this checkout's
existing data, run one of these from the repository root:

```sh
export PROVTRAIL_DATA_DIR="$PWD/corpus/data"
```

```powershell
$env:PROVTRAIL_DATA_DIR = (Resolve-Path corpus/data).Path
```

Optional local Ollama opinions for manual-review findings are enabled with
`--explain-review`; they do not change the detector verdict or exit code.
Use `--help` on any command for the full option list.

See the [advanced guide](guides/advanced-usage.md) for corpus maintenance,
Ollama setup, detector configuration, and implementation details.

## Benchmark

The evaluation measures known-origin retrieval and vulnerable/patched discrimination:

| Dataset | Candidate pool | Purpose |
|---|---:|---|
| Tier 1 | 600 | Labelled targets from original vulnerable and fixed source revisions. |
| Tier 2 | 788 | Transformed vulnerable and patched snippets, including generated variants. |

These are candidate-pool sizes; validation is still in progress. Historical scores
should be read alongside the accepted subset, false positives, and abstentions.
See the [current validation status](eval/tier2/VALIDATION.md) for supported counts
and limitations, and [evaluation commands](eval/README.md) to reproduce experiments.
The [tool-comparison guide](docs/tool-comparison.md) covers comparisons with other scanners.
