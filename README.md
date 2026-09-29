# RedBreach

Full-spectrum security testing platform for bug bounty, pentest, and private assessments. A single async Python CLI that runs a staged recon-to-report pipeline, orchestrating the external tools you already use on Kali and turning their output into scored, deduplicated, platform-ready findings.

> **Authorized use only.** RedBreach is for security testing you are explicitly authorized to perform: your own systems, an in-scope bug bounty program, or a contracted engagement. Running it against systems you do not have written permission to test is illegal in most jurisdictions. Read [Authorized use only](#authorized-use-only) before you use it.

## What it does

- **Staged pipeline.** One engagement runs through recon, web enumeration, web scanning, exploitation, network, and cloud/API/LLM phases, with per-phase control and scope enforcement on every target.
- **Findings, not raw output.** Results are normalized, deduplicated, CVSS v3.1 scored, and mapped to CWE Top 25 and MITRE ATT&CK for coverage reporting.
- **Optional AI assist.** With an `ANTHROPIC_API_KEY` set, findings can be triaged, chained, and rewritten into human-quality report prose. Everything works without it; AI steps are skipped when no key is present.
- **Intel engine.** Local vulnerability intelligence synced from CISA KEV, NVD, ExploitDB, GitHub advisories, OWASP, and the Nuclei template index.
- **Report generation.** Renders findings into platform-specific formats (HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, Immunefi, and a client report), with your own templates able to override the bundled defaults.
- **Extras.** APK static analysis, subdomain takeover checks, a Burp Suite bridge, authenticated scanning profiles, PoC replay verification, and a review gate before anything is reported.

## Requirements

- Python 3.11 or newer
- Linux (developed on Kali; any modern Linux works)
- The external CLI tools each phase drives (recon, scanning, and exploitation binaries). Run `redbreach health` to see what is installed and what is missing. Missing tools are skipped gracefully rather than failing the run.

## Install

From source:

```
git clone https://github.com/Lwesson/RedBreach.git
cd RedBreach
python -m venv .venv && source .venv/bin/activate
pip install -e .                 # base install: works with OpenAI or local models
pip install -e ".[anthropic]"    # add this only if you want to use Claude
```

This installs the `redbreach` command. Verify with `redbreach --help`. The base
install is AI provider neutral; the Anthropic SDK is an optional extra so you only
pull it if you use Claude (see the AI provider section).

## Quickstart

```
# 1. Create an engagement (interactive wizard: type, scope, mode)
redbreach new

# 2. Run the pipeline on that engagement (use the id the wizard prints)
redbreach scan 1                 # full pipeline
redbreach scan 1 --quick         # phases 1-4 only
redbreach scan 1 --speed stealth # stealth | normal | aggressive rate limiting

# 3. Review what came back
redbreach findings list 1
redbreach coverage 1             # CWE Top 25 + ATT&CK coverage

# 4. Verify, review, and report
redbreach verify 1                          # replay PoCs, assess confidence
redbreach review 1                           # approve/reject before reporting
redbreach report generate 42 --platform hackerone
redbreach report generate 42 --platform hackerone --ai   # AI-written prose
```

Run `redbreach <command> --help` for the full options on any command. Other commands include `list`, `resume`, `session`, `auth`, `intel`, `mobile`, `burp`, `score`, and `ops`.

## Configuration and data

RedBreach keeps all runtime state under a data directory, `~/.redbreach/` by default (override with `--data-dir`). The SQLite database, logs, and config live there. Nothing is written into the repository. The AI features are optional and can be powered by Claude, OpenAI, or a local model; see the AI provider section below.

## AI provider (Claude, OpenAI, or a local model)

The AI features (finding triage, exploit chaining, and report writing) are optional and provider agnostic. RedBreach speaks two APIs:

- **Anthropic** (default): Claude models via the native API.
- **OpenAI compatible**: any endpoint that implements `/v1/chat/completions`. One switch covers OpenAI and, by pointing at a local server, self hosted and local models (Ollama, LM Studio, vLLM, llama.cpp) and aggregators such as OpenRouter.

Everything runs without AI too. If no provider is configured, RedBreach skips the AI steps and the rest of the pipeline works normally.

Configure with environment variables (or a `.env` file).

Claude (default; needs the extra: `pip install redbreach[anthropic]`):

```
export ANTHROPIC_API_KEY=sk-ant-...
```

OpenAI:

```
export REDBREACH_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export REDBREACH_AI_MODEL=gpt-4o-mini
```

Local model with Ollama (no API key, nothing leaves your machine):

```
# ollama pull llama3.1   then   ollama serve
export REDBREACH_AI_PROVIDER=openai
export OPENAI_BASE_URL=http://localhost:11434/v1
export REDBREACH_AI_MODEL=llama3.1
```

Local model with LM Studio:

```
export REDBREACH_AI_PROVIDER=openai
export OPENAI_BASE_URL=http://localhost:1234/v1
export REDBREACH_AI_MODEL=<model loaded in LM Studio>
```

Any other OpenAI compatible service works the same way: set `OPENAI_BASE_URL` to its endpoint and `REDBREACH_AI_MODEL` to the model id.

| Variable | Purpose |
|----------|---------|
| `REDBREACH_AI_PROVIDER` | `anthropic` (default) or `openai` |
| `REDBREACH_AI_MODEL` | Model id for the chosen provider |
| `ANTHROPIC_API_KEY` | Key for the Anthropic provider |
| `OPENAI_API_KEY` | Key for the OpenAI provider (any value for a local server that ignores it) |
| `OPENAI_BASE_URL` | OpenAI compatible endpoint, e.g. `http://localhost:11434/v1` |

You can also set these permanently in `~/.redbreach/config.json` under the `ai` block (`provider`, `model`, `base_url`, `budget_dollars`, `max_tokens`). Environment variables override the config file. Budget tracking (`budget_dollars`) applies to models with known pricing; local models are treated as free.

## Report templates

Reports render through Jinja2 templates, one per platform. Sensible defaults ship with the package, so `report generate` works out of the box. To customize, drop your own `<platform>.md` into `~/.redbreach/templates/` (or `<data-dir>/templates/`). Your version overrides the bundled one **per file**: anything you do not provide still uses the default.

Available context variables include `title`, `summary`, `description`, `impact`, `steps_to_reproduce`, `poc_text`, `severity`, `cvss_score`, `cvss_vector`, `cwe`, `attack_technique`, `recommended_fix`, `evidence_files`, `target`, and `report_date`. The bundled templates under `redbreach/templates/` are the reference for what each field renders to.

## Phase 4.5 tool dependencies

The following tools must be installed and on PATH for full Phase 4.5 coverage:

| Tool | Purpose | Install (Debian/Kali) |
|------|---------|----------------|
| `subzy` | Subdomain takeover detection | `go install github.com/PentestPad/subzy@latest` |
| `interactsh-client` | SSRF OAST callbacks | `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| `testssl.sh` | TLS configuration audit | `apt install testssl.sh` |

The `apt` commands are for Debian based distros (Kali, Ubuntu, Debian); on other distros substitute your package manager (for example `dnf` on Fedora, `pacman` on Arch). The `go install` commands are the same everywhere. All Phase 4.5 capabilities skip gracefully (with a debug log) when their tool is missing.

## Development

```
pip install -e ".[dev]"
python -m pytest -q
```

## Authorized use only

RedBreach is built for defensive security and authorized offensive testing. Use it only against systems you own, or that you have explicit, written permission to test. Examples of authorized use are an in-scope public bug bounty program, a contracted penetration test, or your own lab environment.

**Do not use this software to access, scan, probe, or attack any system without authorization.** Unauthorized testing is illegal in most jurisdictions (for example the U.S. Computer Fraud and Abuse Act, and equivalent laws elsewhere) and is not the purpose of this project. You are solely responsible for staying inside the scope you are authorized for and for complying with all applicable laws and program rules.

This project is not intended for malicious use of any kind. The author does not condone or support using it to gain unauthorized access, to harm systems or people, or to break the law, and accepts no liability for misuse. The software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)).

## License

Released under the MIT License. See [LICENSE](LICENSE).
