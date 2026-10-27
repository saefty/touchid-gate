# touchid-gate

Keep CLI secrets behind your fingerprint on macOS.

touchid-gate is one small Swift binary with two jobs:

- **Store:** a drop-in `pass` replacement for tools that use the [99designs/keyring](https://github.com/99designs/keyring) pass backend, such as [Granted](https://github.com/fwdcloudsec/granted). It encrypts each entry to a key that lives in the Secure Enclave, and every read or write needs Touch ID (or your login password, if you choose the `userPresence` policy).
- **Gate:** a Touch ID prompt in front of any command (`terraform apply`, `aws-vault exec`, ...) before it runs.

It has no dependencies beyond Apple frameworks.

> **Read this first.** Your fingerprint is the only real barrier, and the Touch ID dialog cannot prove who asks. Any process running as your user can load the store's key blob and show its own prompt with its own text. Approve that prompt once, and the process can decrypt every entry and forge new ones. touchid-gate stops malware that reads files. It does not stop malware that gets you to touch the sensor. See [Security model](#security-model).

## Why

Granted and similar tools keep SSO tokens and session credentials in the login keychain or in files. Any script, AI agent or piece of malware running as you can read those files, and a keychain item protects them only as far as its access settings reach. With touchid-gate the token sits encrypted on disk, the decryption key never leaves the Secure Enclave, and you approve each use with your finger. The prompt names the calling program and its command line.

[![What happens on every `assume`](docs/overview.png)](docs/overview.png)

## Requirements

- macOS 13 or later
- A Mac with Touch ID and a Secure Enclave
- Swift 5.9 (the Xcode Command Line Tools are enough)

## Build and install

```sh
swift build -c release
swift run selftest                       # optional: runs the self-checks
mkdir -p ~/bin
cp .build/release/touchid-gate ~/bin/
codesign -s - -o runtime -f ~/bin/touchid-gate   # ad-hoc sign with hardened runtime
```

The examples below call `touchid-gate` by name, so put `~/bin` on your `PATH` or use the full path.

The binary picks its mode from the name you call it by. `touchid-gate install` creates the symlinks for that:

| Invoked as | Mode |
|---|---|
| `pass` | store mode: `show`, `insert`, `rm` |
| a configured gate name, e.g. `terraform` | Touch ID prompt, then `exec` of the real binary |
| `touchid-gate` | admin commands: `init`, `install`, `auth` |

## Quick start: Granted

**1. Find Granted's code signature.** Only callers that match it may use the store.

```sh
codesign -d -r- "$(realpath "$(which granted)")"
```

Copy the expression after `designated =>`.

**2. Write `~/.config/touchid-gate/config.json`.** Neither the file nor its directories may be writable by others or carry an ACL that grants access:

```sh
mkdir -p ~/.config/touchid-gate && chmod 700 ~/.config/touchid-gate
touch ~/.config/touchid-gate/config.json && chmod 600 ~/.config/touchid-gate/config.json
```

```json
{
  "stores": {
    "granted": {
      "path": "~/.granted/enclave-store",
      "label": "your AWS SSO login",
      "callers": ["identifier \"granted\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"<TEAMID>\""]
    }
  },
  "gates": {
    "granted":  { "bin": "/opt/homebrew/bin/granted",  "prompt": false, "withPass": true },
    "assumego": { "bin": "/opt/homebrew/bin/assumego", "prompt": false, "withPass": true }
  }
}
```

**3. Create the store key and the links:**

```sh
touchid-gate init granted
touchid-gate install granted
touchid-gate install assumego
touchid-gate install pass
```

**4. Put the gate directory first in your `PATH`:**

```sh
export PATH="$HOME/.local/touchid-gate/bin:$PATH"   # bash/zsh
fish_add_path --prepend ~/.local/touchid-gate/bin  # fish
```

**5. Switch Granted's keyring backend** in `~/.granted/config`:

```toml
[Keyring]
Backend = "pass"
PassDir = "~/.granted/enclave-store"
```

Now run `assume <profile>`. Granted calls `pass show`, and you get a Touch ID prompt that names Granted and the command. After a fresh SSO login, Granted calls `pass insert` and you approve once more to save the token.

The `granted` and `assumego` gates use `"prompt": false`: they add no prompt of their own. They only put touchid-gate's `pass` on Granted's `PATH`. That `pass` lives in `~/.local/touchid-gate/libexec`, outside your normal `PATH`, so a real `pass` installation keeps working for everything else.

## Gates

A gate asks for Touch ID (or your login password) and then `exec`s the real binary:

```json
"gates": {
  "terraform": { "bin": "/opt/homebrew/bin/terraform", "only": ["apply", "destroy"] },
  "aws-vault": { "bin": "/opt/homebrew/bin/aws-vault" }
}
```

```sh
touchid-gate install terraform
```

`only` limits the prompt to the listed subcommands. touchid-gate takes the first argument that does not start with `-` as the subcommand, so `terraform -chdir=x apply` prompts. Flags with a separate value fool it: in `git -C dir push`, it reads `dir`.

Gates are a speed bump. Anyone who calls `/opt/homebrew/bin/terraform` directly skips them.

## Scripts: `touchid-gate auth`

```sh
touchid-gate auth "deploy production" && make deploy
```

Exits 0 when you approve. It accepts the login password as well.

## How-to: `.env` files

You can keep a project's `.env` in a store instead of in plaintext next to the code, and load it with a fingerprint each time.

The caller here is your shell, so the store has to trust zsh (or bash). Both ship with macOS and carry stable Apple signatures. A Homebrew shell such as fish is only ad-hoc signed; its requirement would be a `cdhash` that breaks on every `brew upgrade`. Run the commands below inside zsh.

Trusting zsh means **any zsh process can ask for the secrets**. The caller check filters out other programs, but Touch ID is your only real barrier. The prompt shows the zsh command line, e.g. `zsh -c "docker run ..."` for a script, but just `-zsh` for your interactive shell.

**1. Add a store** to `config.json`:

```json
"env": {
  "path": "~/.local/share/touchid-gate/env",
  "label": "your .env secrets",
  "callers": ["identifier \"com.apple.zsh\" and anchor apple"]
}
```

**2. Create the key.** `init` creates the store directory but not its parents.

```sh
mkdir -m 700 -p ~/.local/share/touchid-gate
touchid-gate init env
touchid-gate install pass   # if you have not done so for Granted
```

**3. Add a helper** to `~/.zshrc`:

```zsh
envpass() { PASSWORD_STORE_DIR=~/.local/share/touchid-gate/env ~/.local/touchid-gate/libexec/pass "$@" }
```

**4. Move a `.env` into the store:**

```zsh
envpass insert -m myapp/env < .env && rm .env
```

`rm` does not scrub the old file from backups or Time Machine. Rotate any secret that matters.

**5. Load it** (one prompt per load):

```zsh
# into the current shell, exported to everything you start from it
set -a; source <(envpass show myapp/env); set +a

# straight into a container or a Node process, never into your shell
docker run --env-file <(envpass show myapp/env) myimage
node --env-file=<(envpass show myapp/env) app.js
```

`source` runs the file as shell code, so only use it for files you wrote. Docker reads values literally: `GREETING="hello world"` arrives with the quotes. Node strips them.

To replace the file, run `envpass insert -m myapp/env < new.env`. To delete it, run `envpass rm myapp/env` (no prompt).

## Configuration

`~/.config/touchid-gate/config.json`. touchid-gate takes the home directory from the user database, not from `$HOME`, and has no environment override for this path. The file and every directory above it up to your home must not be writable by group or others.

| Field | Default | Meaning |
|---|---|---|
| `stores.<name>.path` | required | Store directory, absolute or `~/...`; stores must not nest |
| `stores.<name>.policy` | `biometryCurrentSet` | `biometryCurrentSet`: Touch ID; enrolling a new finger destroys the key. `biometryAny`: Touch ID, survives enrolment changes. `userPresence`: Touch ID or login password. |
| `stores.<name>.callers` | `[]` (nobody) | Code-signing requirements the calling process must meet |
| `stores.<name>.label` | store name | Text for the prompt |
| `stores.<name>.key` | set by `init` | Fingerprint of the store key |
| `gates.<name>.bin` | required | Absolute path of the real binary |
| `gates.<name>.only` | always prompt | Prompt only for these subcommands (must not be empty) |
| `gates.<name>.prompt` | `true` | `false`: no prompt |
| `gates.<name>.withPass` | `false` | Put touchid-gate's `pass` on this tool's `PATH` |

Defaults pick the strict option, so a typo in `callers`, `prompt`, `policy` or `key` locks things down. A typo in `withPass` leaves the tool with whatever `pass` is on its `PATH`. `touchid-gate init` rewrites the file and drops unknown keys and your formatting.

A caller signed with a Developer ID keeps its requirement across updates. Homebrew-built binaries are often only ad-hoc signed; their requirement is a `cdhash` that changes with every `brew upgrade`.

## Security model

**It protects against:**

- a copy of your disk, a backup or Time Machine: entries are encrypted to a Secure Enclave key that only works on this Mac
- other users on the Mac
- processes that only read files, such as scripts or AI agents with file access
- swapped key files, planted or moved entries, symlink and FIFO tricks inside the store
- a process that runs `pass show` itself: touchid-gate checks the caller's code signature

**It does not protect against:**

- **a prompt you approve without having started the command.** Any process running as you can load the store's key blob through CryptoKit and show its own Touch ID prompt with its own text. One approval there decrypts every entry and lets that process forge new ones. Closing this gap needs a Developer ID build with a keychain access group, which an ad-hoc signed binary cannot have.
- credentials already handed to a running command
- a process running as you that rewrites the config, the store key, the binary or the links. touchid-gate checks file permissions, but your own user can change all of them.
- a process that starts `pass` and then turns itself into Granted with `exec`: the caller check looks at the parent's PID, so it is a hurdle, not a boundary
- rolling an entry back to an older genuine version
- root

Rule of thumb: put your finger on the sensor only when you just started the command shown in the prompt.

### Crypto

Each store has one P-256 key in the Secure Enclave. Each entry gets a fresh ephemeral P-256 key, ECDH with the store key, HKDF-SHA256 (bound to the entry name) and AES-256-GCM. An HMAC-SHA256 over the entry protects against planted entries; its key comes from an ECDH between the store key and a public key whose private half `init` throws away, so only the Secure Enclave can compute it. `config.json` pins a SHA-256 fingerprint of the store's public keys and its policy.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) covers the modes, file formats, crypto and threat model in detail. Diagrams:

- [Components and trust boundaries](docs/architecture-components.png)
- [The `assume` flow, step by step](docs/architecture-assume-flow.png)

The `.drawio` sources next to the images open in [draw.io](https://app.diagrams.net) or the draw.io desktop app.

Entries end in `.gpg` because the keyring pass backend looks for that suffix. They contain JSON, not OpenPGP, so the real `pass` cannot read them.

## Limits

- `pass` supports `show`, `insert` and `rm`. Entry names cannot start with `-`.
- Every `pass` call prompts on its own. One `assume` can read several entries and prompt several times.
- `rm` deletes without a prompt. The worst case is a new login.
- With `biometryCurrentSet`, a change to your enrolled fingerprints makes the store unusable. Recover with `rm -r <store>`, `touchid-gate init <store>` and a new login.
- The Secure Enclave fixes a key's policy when `init` creates it. After you change `policy` in the config, the store refuses to work until you run `touchid-gate init <store>` again.
- `touchid-gate init` creates a new key and deletes all entries unless the pinned key is intact and has the configured policy.

## License

[MIT](LICENSE)
