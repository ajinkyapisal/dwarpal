# dwarpal

**Security checks for apps built with AI coding tools.** *Dwarpal* (द्वारपाल)
is the guardian at a temple's gate, who decides what may pass.

AI coding tools ship working apps fast, and they often leave the database wide
open. dwarpal reads your project and tells you, in plain language, what an
attacker could do and exactly how to fix it, with a prompt you can paste
straight into your coding agent.

> Status: early. The first check, for Firebase security rules, is here. More
> checks (leaked keys, vulnerable packages, Supabase, Next.js routes) are
> coming.

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

### How sure are the findings?

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

## Development

```bash
cargo test                      # unit and CLI tests
cd emulator && npm install && npm test   # exploit tests (needs Java 11+)
```
