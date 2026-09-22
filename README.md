# ProvTrail

Find JavaScript and TypeScript code that matches known vulnerable implementations,
including copied or modified code. ProvTrail compares functions against recorded
vulnerable/patched source pairs and produces a local HTML report with upstream
advisories, code comparisons, and evidence for each finding.

## Quick Start

### 1. Install

Requires **Python 3.11+** and **Git**. CPU execution is supported.
Clone the repository:

```sh
git clone https://github.com/ElsonNg/sc4079-fyp.git
cd sc4079-fyp
```

Choose one installation method:

**Virtual environment**

```sh
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on macOS/Linux, or
`.\.venv\Scripts\Activate.ps1` in PowerShell, then install:

```sh
python -m pip install .
```

Use `python -m pip install -e .` instead if you plan to edit the tool.

**pipx: an isolated CLI available from any directory**

With [pipx installed](https://pipx.pypa.io/latest/how-to/install-pipx.html):

```sh
pipx install .
pipx ensurepath
```

Reopen your terminal if the command is not yet on `PATH`.

**Wheel: if you already have a built package**

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

Build the corpus and its search indexes once:

```sh
provtrail corpus build
provtrail corpus stats
provtrail corpus index --device cpu
```

Corpus building and the first embedding-model download require network access and
can take time. Confirm that `corpus stats` reports entries before scanning.

Already have a populated corpus? Skip the build and use
`--db-path /path/to/corpus.db` with `scan` and `corpus stats`. Missing indexes are
built on the first scan. See [data locations](#data-and-configuration) to reuse
existing indexes too.

### 3. Scan a project

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
