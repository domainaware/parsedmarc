# Contributing to parsedmarc

## Setting up the development environment

```bash
git clone https://github.com/domainaware/parsedmarc
cd parsedmarc
pip install -e ".[build,all,dev]"
```

## Running tests

Some tests perform real DNS lookups. To run in offline mode (recommended for local development):

```bash
GITHUB_ACTIONS=true pytest tests/
```

To run a specific test file:

```bash
GITHUB_ACTIONS=true pytest tests/test_config.py -v
```

## Code style

```bash
ruff check .
ruff format .
```

## Type checking

```bash
pyright
```
