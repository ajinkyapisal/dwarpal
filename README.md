# dwarpal

**Security checks for apps built with AI coding tools.** *Dwarpal* (द्वारपाल)
is the guardian at a temple's gate, who decides what may pass.

AI coding tools ship working apps fast, and they often leave the database wide
open. dwarpal reads your project and tells you, in plain language, what an
attacker could do and exactly how to fix it, with a prompt you can paste
straight into your coding agent.

> Status: early. The API and output may change.

## Scan a project

```bash
dwarpal scan            # in your project
dwarpal scan path/to/app --format json
```

```text
dwarpal scan: Next.js · React · Supabase · OpenAI
  secrets in config: checked
  Supabase tables: checked
  gitleaks: checked secrets in code and git history
  trivy: checked vulnerable packages

CRITICAL  Secret exposed to the browser: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY
          .env.local:3
          Next.js puts every variable starting with its public prefix into the JavaScript sent to
          visitors, and its value is a Supabase service_role key. Anyone can open your site, read
          it from the page source, and use it as you.
          Fix: Rename it to SUPABASE_SERVICE_ROLE_KEY (no public prefix), use it only in server
               code, and rotate the key.

CRITICAL  Table `orders` has no row-level security
          supabase/migrations/20260101000000_init.sql:4
          Supabase exposes every table in the public schema through its API. Without row-level
          security, anyone with your anon key, which is in your frontend, can read, change and
          delete every row of `orders`.
```

It works out your stack, runs dwarpal's own checks and the scanners you have
installed, then merges, filters and ranks everything:

| Check | What it finds |
|---|---|
| EX001 | Secrets in `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_` and similar variables, which ship to the browser. Judged by the variable's name and by its value: service_role keys, Stripe, OpenAI and Anthropic keys, database URLs |
| EX002 | The Supabase service_role key used in browser code (`"use client"` files, Vite/Expo `src/`) |
| EX003 | `.env` files with real secrets committed to git |
| EX004 | `.env` files git would commit on the next `git add .` |
| SB001 | Supabase tables without row-level security (from `supabase/migrations`) |
| SB002 | Policies whose condition is `true`, such as the "Allow all for demo" policies AI tools leave behind |
| SB003 | Row-level security turned off |
| FB…, RT… | Firebase rules, see below |
| GL001 | Secrets in code and git history, via [gitleaks](https://github.com/gitleaks/gitleaks) |
| DV001, DV002 | Vulnerable packages, via [Trivy](https://github.com/aquasecurity/trivy) |

**Built to cut noise:**
- **Keys that are public by design are skipped.** That includes Supabase anon and `sb_publishable_` keys (dwarpal decodes Supabase keys to tell anon from service_role), Firebase web API keys, documentation placeholders, and `.env` files that only hold public values (Lovable commits these on purpose).
- **One secret, one finding,** even when it appears in many commits.
- **One finding per vulnerable package** (not one per CVE), with the exact version to upgrade to, and what your current major version can reach if the full fix needs a new major.
- **Packages are judged by how they reach your app:** dev-only tools are reported as low, and indirect packages are grouped into a single "run `npm update`" finding unless something is critical.
- **Problems in your own code rank above dependency issues** of the same severity.

gitleaks and Trivy are optional (`brew install gitleaks trivy`); without them,
dwarpal says what it skipped. `--no-external` runs only dwarpal's own checks.

## Firebase security rules

```bash
dwarpal firebase            # in your project; finds rules through firebase.json
dwarpal firebase firestore.rules storage.rules database.rules.json
```

```text
CRITICAL  Users can make themselves admin by editing their own `role`
          firestore.rules:15
          Other rules trust the `role` field of the caller's own document in users, but this
          rule lets users write their own document at /users/{userId} without restricting
          which fields change. Anyone can set `role` to the value that grants extra access.
          Fix: Stop users from changing `role`, for example:
               allow create, update: if request.auth.uid == userId
                 && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role']);

CRITICAL  Any signed-in user can read, create, change and delete other users' data at /users/{userId}
          firestore.rules:5
          The rule checks that the caller is signed in, but not that {userId} is their own uid.
          Fix: Also require the caller to be the owner, for example:
               allow read, write: if request.auth != null && request.auth.uid == userId;
```

It covers Firestore, Cloud Storage and Realtime Database rules:

| Rule | What it finds |
|---|---|
| FB001 | Rules with no condition or `if true`: anyone on the internet gets in |
| FB002 | Firebase's "test mode" rule left in place (open until a date, then your app breaks) |
| FB003 | Conditions that let people who aren't signed in through |
| FB004 | Per-user paths (`/users/{userId}`) that check sign-in but not *which* user |
| FB005 | "Any signed-in user" rules, including catch-alls like `match /{document=**}` that override every other rule |
| FB006 | Privilege escalation: other rules trust a `role` field users can edit on their own profile |
| FB007 | Storage uploads without size or file-type limits |
| RT001 | Realtime Database paths set to `true` |
| RT002 | Realtime Database test-mode rules (`now < …`) |
| RT003 | Realtime Database conditions that don't involve `auth`, or allow `auth == null` |
| RT004 | Realtime Database paths any signed-in user can access, including other users' `$uid` data |

Every finding includes a fix, and with `--format json` a `prompt` field: a
ready-to-paste instruction for Claude Code, Cursor, Lovable and similar tools.

### Options

```text
--format text|json|sarif     SARIF works with GitHub code scanning
--fail-on critical|high|medium|low|never   (default: high)
```

Exit status: `0` no findings at or above `--fail-on`, `1` findings, `2` a rules
file couldn't be read or parsed.

### How sure are the Firebase findings?

- **Proven against Google's emulator.** `emulator/exploits.test.js` performs the
  actual attack for every kind of finding against the Firebase emulators. Each
  attack must succeed on the insecure test rules and be blocked on the secure ones.
- **Tested on real projects.** The parser and checks were run on 118 real
  rules files from public GitHub repos. All files that Firebase itself would
  accept parse. Every false alarm found was fixed and added as a test.
- **Low noise by design.** `if false`, rules tied to the caller's uid, custom
  claims (`request.auth.token.admin`), role lookups by uid, and field-limited
  updates (`affectedKeys().hasOnly([...])`) are recognised as protected. Public
  reads of a single path are reported as *high*, not *critical*, because they
  are often intentional, like avatars or published posts.
- **It reads rules, not data.** It can't know your intent. A rule that is open on
  purpose will still be reported.

### How the scan was tested

`tests/scan.rs` builds a typical AI-generated Next.js + Supabase app with the
usual mistakes in a temporary git repository and checks every finding, and a
correctly built version that must come back clean. The scan was also run on 30
public Lovable/Bolt-built repositories; every false alarm found there (public
Supabase keys, documentation placeholders, Lovable's committed `.env`, dropped
policies, dependency noise) was fixed and added as a test.

## Development

```bash
cargo test                      # unit, CLI and end-to-end scan tests
cd emulator && npm install && npm test   # exploit tests (needs Java 11+)
```
