# Contributing

Thanks for contributing to parsedmarc.

## Local setup

Use a virtual environment for local development.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install .[build]
```

## Before opening a pull request

Run the checks that match your change:

```bash
ruff check .
pytest --cov --cov-report=xml tests.py
```

If you changed documentation:

```bash
cd docs
make html
```

If you changed CLI behavior or parsing logic, it is also useful to exercise the
sample reports:

```bash
parsedmarc --debug -c ci.ini samples/aggregate/*
parsedmarc --debug -c ci.ini samples/forensic/*
```

To skip DNS lookups during tests, set:

```bash
GITHUB_ACTIONS=true
```

## Pull request guidelines

- Keep pull requests small and focused. Separate bug fixes, docs updates, and
  repo-maintenance changes where practical.
- Add or update tests when behavior changes.
- Update docs when configuration or user-facing behavior changes.
- Include a short summary, the reason for the change, and the testing you ran.
- Link the related issue when there is one.

## Branch maintenance

Upstream `master` may move quickly. Before asking for review or after another PR
lands, rebase your branch onto the current upstream branch and force-push with
lease if needed:

```bash
git fetch upstream
git rebase upstream/master
git push --force-with-lease
```

## CI and coverage

GitHub Actions is the source of truth for linting, docs, and test status.

Codecov patch coverage is usually the most relevant signal for small PRs. Project
coverage can be noisier when the base comparison is stale, so interpret it in
the context of the actual diff.

## Questions

Use GitHub issues for bugs and feature requests. If you are not sure whether a
change is wanted, opening an issue first is usually the safest path.
