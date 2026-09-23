[vexa](./images/vexa.png)
# Vexa

**Vexa** is a command-line JWT security analyzer for authorized security assessment, penetration testing, and application security testing.

It inspects JWT structure, headers, claims, algorithms, signatures, token lifetime, and sensitive claim names. It can also compare tokens, analyze many tokens at once, and inspect a JWKS document or OpenID Provider metadata when you name the target.

Use Vexa only on applications, APIs, tokens, keys, and infrastructure you own or are explicitly allowed to assess.

## Run it

After installation, the command is `vexa`.

```bash
vexa -h
vexa --help
vexa <command> -h
```

`vexa -h` prints every command, the operating modes, the shared flags, and the exit codes.

Before the `vexa` script is on your `PATH`, the same interface is:

```bash
python -m jwt_analyzer -h
```

## Install

From the `vexa_cli` directory:

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
python -m pip install -e .
```

macOS and Linux:

```bash
source .venv/bin/activate
python -m pip install -e .
```

Requires Python 3.9 or newer. The runtime dependency is `cryptography`.

Check the install:

```bash
vexa -h
vexa version
```

## Commands

```text
vexa
├── decode     Decode one JWT
├── analyze    Offline analysis (fast mode)
├── assess     Assessment mode: OIDC discovery and JWKS
├── verify     Check a signature with a key, secret, or JWKS
├── compare    Diff two or more JWTs
├── batch      Analyze a directory or a line-oriented file
├── jwks       Inspect a local or remote JSON Web Key Set
├── oidc       Inspect OpenID Provider discovery metadata
├── report     Render a saved JSON analysis in another format
└── version    Print the installed version
```

### Decode

Print the header, payload, and metadata. This does not score findings and does not use the network.

```bash
vexa decode token.jwt
vexa decode "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"
```

A token argument may be a compact JWT or a file that contains one.

### Analyze

Fast mode. Header, claim, lifetime, and local structure checks stay offline.

```bash
vexa analyze token.jwt
```

`fast` and `passive` are the same offline mode. `assessment` on this command contacts the issuer you name:

```bash
vexa analyze token.jwt --mode assessment --issuer https://auth.example.com
```

### Assess

Assessment mode always expects a remote target. Pass `--issuer` or `--jwks-url`.

```bash
vexa assess token.jwt --issuer https://auth.example.com
vexa assess token.jwt --jwks-url https://auth.example.com/.well-known/jwks.json
```

Vexa fetches OpenID Provider metadata when an issuer is given, loads the advertised JWKS, and includes those checks in the report. It does not scan hosts you did not name.

### Verify

Pass exactly one key source.

```bash
vexa verify token.jwt --public-key public.pem
vexa verify token.jwt --secret "hmac-secret"
vexa verify token.jwt --jwks-file jwks.json
vexa verify token.jwt --jwks-url https://auth.example.com/.well-known/jwks.json
```

`--public-key` is a PEM public key or certificate file. `--secret` is the HMAC secret itself, not a path. JWKS selection uses the token `kid`.

Supported signature algorithms:

```text
HS256  HS384  HS512
RS256  RS384  RS512
ES256  ES384  ES512
```

`alg: none` is reported as a finding and is not treated as a successful verification.

### Compare

```bash
vexa compare token1.jwt token2.jwt
vexa compare baseline.jwt later.jwt --no-color
```

The report shows claim and header differences, including privilege-related changes such as role, scope, and audience.

### Batch

```bash
vexa batch ./tokens
vexa batch --file tokens.txt
vexa batch ./tokens --workers 4
```

A directory is read as one token per file. `--file` is a text file with one JWT per line. Pass a path or `--file`, not both.

### JWKS

```bash
vexa jwks ./jwks.json
vexa jwks https://example.com/.well-known/jwks.json
vexa jwks https://example.com/.well-known/jwks.json --token token.jwt
```

The report includes key type, use, algorithm, and `kid`. `--token` matches the JWT to a key and checks the signature when the key type allows it.

### OIDC

```bash
vexa oidc https://auth.example.com
vexa oidc https://auth.example.com --token token.jwt
```

Vexa reads `/.well-known/openid-configuration` and reports fields such as `issuer`, `jwks_uri`, signing algorithms, response types, grant types, scopes, and claims. `--token` compares the JWT `iss` and `alg` with that document.

### Report

`analyze` and `assess` can write JSON. `report` renders that file again.

```bash
vexa analyze token.jwt --json -o result.json
vexa report result.json --format html -o report.html
vexa report result.json --format markdown
vexa report result.json --format csv
vexa report result.json --format text
```

## Reports

`analyze` and `assess` accept one format:

```bash
vexa analyze token.jwt
vexa analyze token.jwt --json
vexa analyze token.jwt --html report.html
vexa analyze token.jwt --format markdown -o report.md
vexa analyze token.jwt --format csv -o report.csv
vexa analyze token.jwt --format json -o report.json
```

| Format | How to select it |
| --- | --- |
| Text | Default. Also `--format text` or `--format terminal` |
| JSON | `--json` or `--format json` |
| HTML | `--html report.html` or `--format html -o report.html` |
| Markdown | `--format markdown` |
| CSV | `--format csv` |

`--html` without a path prints the HTML document. `--color` and `--no-color` apply to the text report. A text report on a terminal is colored unless you pass `--no-color` or set `report.color: false`.

A text report includes token metadata, each finding (id, title, severity, confidence, description, evidence, impact, remediation), severity counts, and a risk score from 0 to 100.

## What the analyzers check

Offline analysis covers:

- Compact JWT structure, Base64url segments, and JSON objects
- Header algorithm, type, `kid`, `jku`, `x5u`, and `jwk`
- `alg: none` and other weak or mismatched algorithms
- Registered claims: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`
- Missing, invalid, expired, or inconsistent timestamps
- Token lifetime above `analysis.max_token_lifetime` (default 3600 seconds)
- Duplicate claims
- Claim names that look sensitive (`password`, `secret`, `token`, `api_key`, `private_key`, `authorization`, `credit_card`, and close variants). Values are masked in findings

Assessment and the `jwks` / `oidc` commands add remote configuration checks only for the URL you pass: discovery metadata, advertised algorithms, key metadata, `kid` matching, and signature verification.

Each finding has an id, title, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), confidence, description, evidence, impact, and remediation.

## Configuration

Flags override the file. If you omit `--config`, Vexa loads the first file that exists:

```text
~/.vexa.yaml
~/.vexa.yml
~/.vexa.json
```

Older `~/.jwt-analyzer.yaml`, `~/.jwt-analyzer.yml`, and `~/.jwt-analyzer.json` files are still read when no `.vexa.*` file is present.

```yaml
mode: fast
issuer: https://auth.example.com
log_level: WARNING
analysis:
  max_token_lifetime: 3600
  check_sensitive_claims: true
  check_duplicate_claims: true
security:
  severity_threshold: HIGH
report:
  format: text
  color: true
ignore:
  - JWT-EXP-001
```

`mode` is `fast`, `passive`, or `assessment`. `passive` is stored as fast mode. `report.format` may be `text`, `terminal`, `json`, `html`, `markdown`, or `csv`.

```bash
vexa analyze token.jwt --config ./vexa.yaml --severity-threshold HIGH --ignore-rule JWT-EXP-001
```

There is no `--max-lifetime` flag. Set the lifetime limit with `analysis.max_token_lifetime` in the config file.

## Shared flags

Place these after the command name.

| Flag | Effect |
| --- | --- |
| `--config PATH` | YAML or JSON defaults. Later flags replace the file |
| `--ignore ID` | Suppress one finding id |
| `--ignore-rule ID` | Same as `--ignore` |
| `--severity-threshold LEVEL` | `analyze` and `assess` exit 1 at this severity or above. Default: `HIGH` |
| `--verbose` | Log progress to stderr |
| `--debug` | Log debug details to stderr |
| `--log-level LEVEL` | `ERROR`, `WARN`, `INFO`, `DEBUG`, or `TRACE` |

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | No finding at or above the severity threshold |
| 1 | A finding meets the threshold, or signature verification failed |
| 2 | Invalid input |
| 3 | Configuration error |
| 4 | Runtime error |

Example CI check:

```bash
vexa analyze token.jwt --severity-threshold HIGH --format json -o report.json
```

Exit code 1 fails the job when a finding is `HIGH` or `CRITICAL`.

## Modes

**Fast / passive.** `vexa analyze` does not contact the network.

**Verify.** Signature checks use only the key, secret, or JWKS you pass.

**Assessment.** `vexa assess`, `vexa jwks <url>`, and `vexa oidc <issuer>` fetch only the URL you provide. Redirects stay on HTTP(S), credentials in the URL are rejected, the response body is size-capped, and the client times out.

## Project layout

```text
vexa_cli/
├── pyproject.toml          # installs the vexa command
├── src/jwt_analyzer/
│   ├── main.py             # vexa entry point
│   ├── cli.py              # commands and flags
│   ├── parser.py
│   ├── config.py
│   ├── engine.py           # analyzer chain and risk score
│   ├── findings.py
│   ├── http_client.py
│   ├── analyzers/
│   │   ├── header.py
│   │   ├── payload.py
│   │   ├── crypto.py
│   │   ├── jwks.py
│   │   ├── oidc.py
│   │   ├── compare.py
│   │   └── batch.py
│   └── reporters/
│       ├── text_reporter.py
│       ├── json_reporter.py
│       ├── html_reporter.py
│       ├── markdown_reporter.py
│       └── csv_reporter.py
└── tests/
    ├── unit/
    ├── integration/
    └── fuzz/
```

The import package remains `jwt_analyzer`. The command you run is `vexa`.

## Tests

From `vexa_cli`, with the dev extra:

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m pytest tests/unit tests/integration --cov=jwt_analyzer --cov-report=term-missing --cov-fail-under=80
python tests/fuzz/run_fuzz.py --seconds 300
```

GitHub Actions (`.github/workflows/test.yml`) runs the unit tests, integration tests, and parser fuzz corpus. Coverage must stay above 80 percent.

## Stack

| Piece | Choice |
| --- | --- |
| Language | Python 3.9+ |
| CLI | argparse (`vexa`, `vexa -h`) |
| Signatures | cryptography |
| Remote fetch | Python `urllib`, only for a URL you pass |
| Tests | pytest |

## Disclaimer

Vexa is an analysis and verification tool. It is not an exploit framework. Test only systems and tokens you are authorized to assess.
