# Contributing to RedBreach

Thanks for your interest in improving RedBreach. This guide covers how to set up
a development environment, the standards for changes, and how to get them merged.

## Authorized use first

RedBreach is a security testing tool for authorized use only. Contributions must
keep that intent. Do not add features whose only purpose is to help someone
attack systems they are not permitted to test, to evade authorization or scope
controls, or to remove the safeguards that keep testing inside an approved
scope. See the "Authorized use only" section of the [README](README.md).

## Getting started

```
git clone https://github.com/Lwesson/RedBreach.git
cd RedBreach
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11 or newer. Run `redbreach health` to see which external tools
are installed; missing tools are skipped gracefully, so you do not need all of
them to develop.

## Running the tests

```
python -m pytest -q
```

The suite should be fully green before and after your change. Add tests for any
new behavior or bug fix. Tests must not reach the network or a real target: mock
external tools and HTTP calls, and use synthetic data (`example.com`,
`example.org`, and the documentation IP range) as the existing fixtures under
`tests/fixtures/` do.

## Coding standards

- Match the style of the surrounding code.
- Validate inputs, handle tool and API failures gracefully, and never let bad
  data propagate silently.
- Never commit secrets, credentials, real target data, or personal information.
  `.gitignore` and `.gitleaks.toml` are set up to help (run `gitleaks detect`
  before pushing), but the final check is yours.
- Keep runtime state under the data directory (`~/.redbreach/` by default), never
  written into the repository.

## Adding a report template

Report templates live in `redbreach/templates/` as `<platform>.md` Jinja2 files,
one per platform. To add support for a new platform, add the template there and
include the platform in `SUPPORTED_PLATFORMS` in
`redbreach/reporting/generator.py`. Users can override any bundled template by
dropping their own `<platform>.md` in `~/.redbreach/templates/`, so keep the
context variables consistent with the existing templates.

## Submitting changes

1. Open an [issue](https://github.com/Lwesson/RedBreach/issues) to discuss
   larger changes before you start.
2. Create a branch for your work.
3. Make the change, add tests, and confirm `python -m pytest -q` is green.
4. Open a [pull request](https://github.com/Lwesson/RedBreach/pulls) with a clear
   description of what changed and why.

## Reporting bugs and requesting features

Use the repository [issues](https://github.com/Lwesson/RedBreach/issues). For
security vulnerabilities in RedBreach itself, do not open a public issue; follow
the process in [SECURITY.md](SECURITY.md) instead.
