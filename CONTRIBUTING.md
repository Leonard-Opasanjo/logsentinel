# Contributing

Thanks for looking. Bug reports, detection ideas and pull requests are welcome.

## Set up

```bash
git clone https://github.com/Leonard-Opasanjo/logsentinel.git
cd logsentinel
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

Run the same checks CI runs:

```bash
ruff check .
pytest
bandit -q -c pyproject.toml -r src
pip-audit
```

If you touched `scripts/make_sample_log.py`, regenerate the bundled log with `python scripts/make_sample_log.py`
and update the expected counts in `tests/test_cli.py` and `tests/test_app.py`. CI checks that the committed log
matches the generator.

## Adding a detection rule

1. Write a function in `src/logsentinel/detect.py` with the signature `rule(ev: pd.DataFrame, cfg: Config) -> list[Finding]`.
   Work from the `ev` DataFrame (columns are listed in `parser.COLUMNS`), never from the raw text.
2. Give each finding a plain-language title, a description that says why it fired, a recommendation, the line numbers
   as evidence, and one of the four severities.
3. Add it to the `RULES` tuple. Thresholds go on `Config` with validation in `__post_init__`, a CLI flag in `cli.py`
   and a slider in `app.py`.
4. Add tests in `tests/test_detect.py` that cover the threshold edge (fires at N, not at N-1) and an empty frame.
5. Add a row to the table in `README.md`.

## Adding a log format

Parsing lives in `src/logsentinel/parser.py`. Add a regex to `_SSHD` or `_SUDO` (or a new family in `_classify`),
and a fixture line in `tests/test_parser.py`. Keep the event names stable; the rules depend on them.

## Style

- `ruff` settings in `pyproject.toml` are the style guide. Line length 120.
- Keep functions small and free of I/O; the CLI and the dashboard are the only places that read files or print.
- Do not add dependencies for something the standard library or pandas already does.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.
