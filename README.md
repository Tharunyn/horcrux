# HORCRUX

> **Offline Threshold Key Management System for Blockchain Private Keys**

[![CI](https://github.com/rishi-xyz/horcrux/actions/workflows/ci.yml/badge.svg)](https://github.com/rishi-xyz/horcrux/actions/workflows/ci.yml)

HORCRUX is a Rust-based offline threshold key management system that eliminates the single point of failure associated with traditional cryptocurrency wallets. Instead of storing an entire private key on one device, HORCRUX distributes cryptographic control across multiple trusted guardians using **Shamir's Secret Sharing (SSS)** and supports **FROST threshold Multi-Party Computation (MPC)** for secure transaction signing.

Designed for self-custody, security-critical environments, and blockchain infrastructure, HORCRUX enables users to securely split, store, recover, and sign blockchain transactions without relying on cloud providers or centralized custody services.

Unlike traditional wallets, HORCRUX treats key management as an entire lifecycle rather than a single storage problem.

---

## Table of Contents

- Introduction
- Why HORCRUX?
- Features
- Project Objectives
- System Overview
- Core Concepts
- System Workflow
- Project Architecture
- Project Modules
- Technology Stack
- Repository Structure
- Installation
- Building
- Usage
- CLI Commands
- Interactive TUI & Local Web UI
- Access Logging, AI Checks & Risk Assessment
- Cryptographic Design
- Security Model
- Threat Model
- Demo Script
- Marketing Site
- Contributing & CI
- Future Roadmap
- References
- License

---

# Why HORCRUX?

Private keys remain the weakest point in blockchain security.

Existing wallet architectures generally suffer from one or more of the following issues:

- Single device failure
- Plaintext backups
- Vendor dependence
- Internet dependency
- Expensive hardware requirements
- Limited recovery options

HORCRUX addresses these limitations by introducing a completely offline threshold key management workflow.

Instead of protecting one secret, HORCRUX protects multiple encrypted fragments of that secret.

Each fragment is:

- individually encrypted
- password protected
- stored on a dedicated USB drive
- owned by a different guardian

Only when the required threshold of guardians cooperate can a transaction be signed.

---

# Features

## Offline First

Every critical cryptographic operation can be performed completely offline.

Private keys never need internet connectivity.

---

## Threshold Cryptography

Supports configurable threshold schemes including

- 2-of-3
- 3-of-5
- 5-of-7
- N-of-M

using Shamir's Secret Sharing.

---

## USB Bound Storage

Each shard is physically written to a guardian USB device.

Stealing one USB does not compromise the key.

---

## Password Hardened Encryption

Every shard is encrypted using

- AES-256-GCM
- Argon2id
- Random Salt
- Authentication Tag

before leaving memory.

---

## Dual Signing Modes

### Mode A

Air-gapped reconstruction.

Private key exists only inside locked RAM for a few milliseconds before being securely erased.

### Mode B

True Threshold MPC (FROST).

The private key never exists on any machine.

Guardians each hold one encrypted key share and collaboratively produce a
valid Ed25519 signature without the key ever being reconstructed.

---

## Solana Compatible

Uses

- Ed25519 for signing
- secp256k1 field for Shamir secret sharing
- Compatible with Solana (local validator, devnet)

---

## Memory Safety

Implemented in Rust.

Sensitive memory is wiped immediately after use using secure zeroization.

---

## AI-Based Behavioral Security

Beyond cryptography, HORCRUX includes behavioral anomaly detection capable of identifying:

- unusual signing times
- repeated password failures
- abnormal guardian participation
- suspicious access patterns

---

# Project Objectives

HORCRUX aims to solve the complete lifecycle of blockchain private key management.

The primary objectives are:

- Eliminate single-point key storage.
- Securely split keys using threshold cryptography.
- Bind shards to physical USB devices.
- Encrypt every shard independently.
- Support offline signing.
- Support threshold MPC signing.
- Preserve compatibility with Solana (Ed25519).
- Detect suspicious access behavior.
- Maintain complete self custody.

---

# System Overview

HORCRUX consists of three primary operational phases.

```
                Setup
                   │
                   ▼
         Split Private Key
                   │
                   ▼
          Encrypt Each Shard
                   │
                   ▼
          Write To USB Drives
                   │
      ─────────────────────────
                   │
             Distribution
                   │
                   ▼
        Guardian Storage Phase
                   │
      ─────────────────────────
                   │
              Signing Phase
          ┌────────────────┐
          │                │
          ▼                ▼
      Mode A           Mode B
      Air Gap            MPC
```

---

# Core Concepts

## Shamir Secret Sharing

The original private key is mathematically divided into **N** independent shares.

A configurable threshold **T** determines the minimum number of shares required for reconstruction.

Example:

```
Secret

↓

Split

↓

Shard A
Shard B
Shard C

Threshold = 2

A+B ✔
A+C ✔
B+C ✔

Only A ✘
Only B ✘
Only C ✘
```

Any subset smaller than the threshold reveals no information about the original secret.

---

## Guardian Model

HORCRUX introduces the concept of **Guardians**.

Each guardian owns:

- one encrypted shard
- one USB drive
- one password

No guardian possesses the complete key.

---

## Two-Factor Custody

Every shard requires:

Physical possession

AND

Knowledge of the guardian password.

Stealing only the USB drive is insufficient.

Knowing only the password is insufficient.

---

## Air-Gapped Security

Mode A enables completely offline signing.

Network connectivity is unnecessary.

Suitable for:

- cold wallets
- treasury management
- institutional custody
- high value transactions

---

## Threshold MPC

Mode B uses FROST threshold Ed25519 signing (RFC 9591).

Instead of reconstructing the private key:

```
Guardian A

+

Guardian B

+

Guardian C

↓

Signature Shares

↓

Coordinator

↓

Valid Ed25519 Signature
```

The private key never appears anywhere.

---

# System Workflow

## Phase 1

Initialization

```
Private Key

↓

HORCRUX CLI

↓

SSS Module

↓

Generate N Shards
```

---

## Phase 2

Shard Protection

```
Guardian Password

↓

Argon2id

↓

AES-256 Key

↓

AES-GCM Encryption

↓

Encrypted Shard
```

---

## Phase 3

Distribution

```
Encrypted Shard

↓

USB Drive

↓

Guardian
```

---

## Phase 4

Signing

Two execution modes exist.

### Mode A

```
USB

↓

Decrypt

↓

Reconstruct Key

↓

Sign Transaction

↓

Zeroize Memory

↓

Output Signed Transaction
```

---

### Mode B

```
Guardian 1

↓

Guardian 2

↓

Guardian 3

↓

FROST Threshold Protocol

↓

Ed25519 Signature

↓

Broadcast
```

---

# Project Architecture

The project is divided into multiple independent cryptographic modules.

```
HORCRUX
│
├── CLI
├── Config
├── Authentication
├── SSS Module
├── Encryption Module
├── USB Storage
├── MPC Module
├── Signing Module
├── Blockchain Module
├── AI Module
└── Logging Module
```

Each module has a clearly defined responsibility to simplify auditing, testing, and future extension.

---

# Technology Stack

| Layer | Technology |
|----------|------------|
| Language | Rust |
| CLI | clap |
| TUI | ratatui + crossterm + tui-input |
| Secret Sharing | vsss-rs |
| Encryption | AES-256-GCM |
| Password KDF | Argon2id |
| Zeroization | zeroize |
| Elliptic Curve | Ed25519 (Solana signing), secp256k1 (Shamir field, Bitcoin/Cosmos signing) |
| Chain Integration | solana-rpc-client (Solana), bitcoincore-rpc (Bitcoin), cosmrs::rpc / tendermint-rpc (Cosmos) |
| MPC | FROST (frost-ed25519 for Solana, frost-secp256k1-tr for Bitcoin Taproot) |
| Air-gapped transport | HX3 frames over QR-code PNGs (`qrcode` + `image` + `rqrr`) or `.hx3` files |
| AI | Rule-based scorer (z-scores + hard rules) |
| Serialization | serde |
| Storage | Binary Shard Files |
| USB Medium | FAT32 / exFAT Drives |

---

# Repository Structure

```
horcrux/
│
├── src/
│   ├── main.rs         CLI (clap)
│   ├── lib.rs          split/encrypt/reconstruct pipeline
│   ├── sss.rs          Shamir split & combine (vsss-rs)
│   ├── crypto.rs       Argon2id + AES-256-GCM
│   ├── shard.rs        HX1 shard file format
│   ├── mpc.rs          Mode B FROST split & threshold sign (Solana/Ed25519)
│   ├── btc_mpc.rs      Mode B FROST split & threshold sign (Bitcoin/secp256k1-tr)
│   ├── qr.rs           HX3 frame format + QR-code PNG transport
│   ├── qr_mpc.rs       air-gapped FROST protocol over HX3 messages
│   ├── tx.rs           offline Solana transaction build/sign
│   ├── bitcoin.rs      offline Bitcoin Taproot transaction build/sign
│   ├── cosmos.rs       offline Cosmos bank.MsgSend build/sign
│   ├── chain.rs        Solana RPC broadcast / blockhash / balance
│   ├── audit.rs        access log + anomaly scorer
│   ├── verify.rs       passive shard integrity checks
│   ├── error.rs        typed error enum
│   ├── tui/            interactive terminal UI (`horcrux tui`)
│   └── web/            local loopback-only web UI (`horcrux web`)
│
├── site/               marketing/docs site (Next.js + React + Tailwind CSS — install guide, demo video slot)
│
├── tests/
│   ├── roundtrip.rs
│   ├── sign.rs
│   ├── audit.rs
│   ├── mpc.rs
│   ├── btc_mpc.rs
│   ├── qr.rs
│   └── verify.rs
│
├── agent/wayfinder/PLAN.md
├── Architecture.md
├── CONTRIBUTING.md   contribution + release workflow
├── demo.sh
├── Cargo.toml
├── LICENSE
├── README.md
└── .github/
    ├── workflows/
    │   ├── ci.yml        PR/push verification on main
    │   └── release.yml   tag-triggered binary release
    └── dependabot.yml    dependency update PRs
```
---

# Installation

## Prerequisites

Before building HORCRUX, ensure the following tools are installed.

| Requirement | Version |
|-------------|---------|
| Rust | Stable (latest) |
| Cargo | Latest |
| Git | Latest |
| USB Drive(s) | Recommended |
| Linux / macOS / Windows | Supported |
| solana-test-validator | Optional (live broadcast demo) |

Verify your installation:

```bash
rustc --version
cargo --version
```

---

## Clone Repository

```bash
git clone https://github.com/<username>/horcrux.git

cd horcrux
```

---

## Build

Development

```bash
cargo build
```

Release

```bash
cargo build --release
```

The executable will be available at

```
target/release/horcrux
```

---

## Running Tests

Run all tests

```bash
cargo test
```

Run integration tests

```bash
cargo test --tests
```

Run documentation tests

```bash
cargo test --doc
```

---

## Linting

```bash
cargo fmt

cargo clippy
```

---

# Getting Started

A typical HORCRUX workflow consists of four steps.

```
Generate Wallet

↓

Initialize HORCRUX

↓

Distribute USB Shards

↓

Sign Transactions
```

---

# CLI Commands

HORCRUX exposes a simple command-line interface.

```
horcrux
├── init
├── reconstruct
├── sign          (--chain solana|bitcoin|cosmos)
├── mpc-split     (--chain solana|bitcoin)
├── mpc-sign      (--chain solana|bitcoin)
├── qr-request    (Mode B over an air-gapped QR transport)
├── qr-commit
├── qr-package
├── qr-share
├── qr-finalize
├── verify
├── log
├── tui           (interactive terminal UI)
├── web           (local, loopback-only web UI)
└── help
```

---

## Initialize

Creates encrypted shards from a private key.

```bash
horcrux init
```

Example

```bash
horcrux init \
    --threshold 2 \
    --shares 3 \
    --out-dir ./usb
```

Process

```
Private Key

↓

Split

↓

Encrypt

↓

Write USB Shards

↓

Destroy Original Key
```

---

## Sign

Mode A signing: decrypt a threshold of shards, reconstruct the key in RAM, build and
sign a Solana transaction offline, wipe the key, and output the signed transaction.

```bash
horcrux sign \
    ./usb/shard-1.hx ./usb/shard-2.hx \
    --password guardian \
    --to RecipientAddressBase58 \
    --lamports 1000000000 \
    --blockhash <recent-base58-blockhash>
```

(`--password` applies to every shard; omit it to be prompted per shard.)

- Required: `--to` (base58), `--lamports` (1 SOL = 1_000_000_000 lamports), and
  `--blockhash`. A blockhash must be supplied offline; it is only valid for the
  block window in which it was produced, so fetch a fresh one at signing time
  (e.g. `solana blockhash`).
- Optional: `--rpc-url` (overrides `$HORCRUX_RPC_URL`, default
  `http://127.0.0.1:8899`) and `--broadcast`.
- Audit: `--log-file` (default `./horcrux-access.log` or `$HORCRUX_ACCESS_LOG`)
  records every shard decryption, and `--force` bypasses an audit block.

Broadcast to the cluster (local validator by default), fetching the latest
blockhash and waiting for confirmation:

```bash
HORCRUX_RPC_URL=http://127.0.0.1:8899 \
horcrux sign \
    ./usb/shard-1.hx ./usb/shard-2.hx \
    --password guardian \
    --to RecipientAddressBase58 \
    --lamports 1000000000 \
    --broadcast
```

The sender address is derived from the reconstructed key; when broadcasting,
its balance is checked (airdrop lamports first with `solana airdrop 1 <addr>`).

### Other chains

`--chain` selects the chain (default `solana`); the same reconstructed
secp256k1/Ed25519 seed signs all three, so one shard set spends from every
chain's derived address.

**Bitcoin** (offline Taproot key-path signing, BIP340/341/342):

```bash
horcrux sign \
    ./usb/shard-1.hx ./usb/shard-2.hx --password guardian \
    --chain bitcoin \
    --to bc1p... \
    --utxo <txid>:<vout>:<amount-sat> \
    --amount-sat 60000 --fee-sat 10000
```

`--utxo` repeats per input. `--change-address` defaults to the sender's own
P2TR address. `--broadcast` calls a Bitcoin Core node's `sendrawtransaction`
(default `http://127.0.0.1:18443`, a regtest node; override with `--rpc-url`
or `$HORCRUX_BTC_RPC_URL`, and authenticate with `--rpc-user`/
`--rpc-password` if the node requires it).

**Cosmos** (offline `bank.MsgSend`, `SIGN_MODE_DIRECT`):

```bash
horcrux sign \
    ./usb/shard-1.hx ./usb/shard-2.hx --password guardian \
    --chain cosmos \
    --to cosmos1... --chain-id cosmoshub-4 \
    --account-number 12345 --sequence 0 \
    --amount 1000000 --denom uatom \
    --gas 100000 --fee 5000
```

`--broadcast` calls a Tendermint RPC node's `/broadcast_tx_commit` (default
`http://127.0.0.1:26657`; override with `--rpc-url` or
`$HORCRUX_COSMOS_RPC_URL`) and waits for the transaction to be included in a
block; a non-OK `CheckTx`/delivery result is reported as an error rather than
a silent "success".

Output

```
Signed Transaction

↓

Raw Base58 (bincode)

↓

Broadcast (opt-in)
```

---

## MPC Signing (Mode B)

FROST threshold signing: dealer-split a key into encrypted key shares, then
sign with any threshold subset. The full signing key is never reconstructed on
any machine.

Split the key (writes `mpc-{id}.hx` share files plus a non-secret
`group.pub`):

```bash
horcrux mpc-split \
    --threshold 2 \
    --shares 3 \
    --out-dir ./mpc
```

Sign with a threshold subset of share files:

```bash
horcrux mpc-sign \
    ./mpc/mpc-1.hx ./mpc/mpc-2.hx \
    --group-dir ./mpc \
    --password guardian \
    --to RecipientAddressBase58 \
    --lamports 1000000000 \
    --blockhash <recent-base58-blockhash>
```

Each share file is its own in-process participant in the two-round FROST
protocol (round 1: nonce commitments, round 2: signature shares), which the
coordinator aggregates into a single Ed25519 signature. Only nonces,
commitments, and signature shares ever exist in memory.

- Flags mirror `sign`: `--broadcast` (plus optional `--rpc-url`) fetches the
  blockhash and broadcasts; `--log-file`/`$HORCRUX_ACCESS_LOG` records every
  participant decrypt plus a final `signed` entry; `--force` overrides an audit
  block.
- The group address (the `From` line) equals the Mode A wallet address, so a
  FROST-signed transaction is indistinguishable from one signed with the full
  key — and can be broadcast to Solana unchanged.

Mode B flow:

```
Decrypt Each Key Share
↓
Round 1: Nonce Commitments
↓
Round 2: Signature Shares
↓
Aggregate
↓
Valid Ed25519 Signature
```

### Bitcoin Mode B

`--chain bitcoin` on both `mpc-split` and `mpc-sign` runs the identical
protocol over `frost-secp256k1-tr` (Zcash Foundation) instead of
`frost-ed25519`, producing a BIP340 Schnorr signature under the BIP341
Taproot tweak:

```bash
horcrux mpc-split --chain bitcoin --threshold 2 --shares 3 --out-dir ./btc-mpc
horcrux mpc-sign \
    ./btc-mpc/btc-mpc-1.hx ./btc-mpc/btc-mpc-2.hx \
    --chain bitcoin --group-dir ./btc-mpc --password guardian \
    --to bc1p... --utxo <txid>:<vout>:<amount-sat> \
    --amount-sat 60000 --fee-sat 10000
```

Bitcoin share files use their own `HX4` magic (distinct from Solana's `HX2`
and the SSS `HX1`, and from each other's `group.pub`/`group-btc.pub`), so
files from different chains or protocols can never be cross-used. The
tweaked group address equals the Bitcoin Mode A address for the same seed.
`--chain cosmos` is rejected on both commands: Cosmos uses plain
ECDSA/secp256k1, which needs a different threshold protocol
(GG18/GG20/CGGMP21 — multiplicative-to-additive share conversion, Paillier
encryption, zero-knowledge proofs) than FROST/Schnorr, and no mature audited
Rust crate for it exists yet, so it is a deliberate scope boundary rather
than an oversight.

---

## Air-Gapped QR Signing (Mode B over a real air gap)

`qr-request` / `qr-commit` / `qr-package` / `qr-share` / `qr-finalize` run
the same Solana FROST protocol as `mpc-sign`, but every protocol message
(the signing request, each commitment, the signing package, each signature
share) crosses as a real, independently scannable QR-code PNG file — or a
`.hx3` file when a camera isn't available — instead of an in-process call.
No process ever holds more than one participant's key share; the two
machines never need to be on the same network, or even the same room, at the
same time.

```bash
# Coordinator: build the request
horcrux qr-request --group-dir ./mpc --to RecipientAddressBase58 \
    --lamports 1000000000 --blockhash <recent-base58-blockhash> --dir ./qr

# Each guardian (physically carries ./qr's PNGs to their own machine):
horcrux qr-commit ./mpc/mpc-1.hx --password guardian --dir ./qr

# Coordinator: once enough commitments have arrived
horcrux qr-package --dir ./qr

# Each guardian again, after the package PNG arrives:
horcrux qr-share ./mpc/mpc-1.hx --password guardian --dir ./qr

# Coordinator: once enough signature shares have arrived
horcrux qr-finalize --dir ./qr --broadcast
```

- `--dir` is the "air gap": in a real deployment each step's output PNG is
  photographed off one screen and scanned into the next machine; this CLI
  writes/reads the same directory for scriptability, but the files are
  exactly what would be encoded into and decoded from a physical QR code.
- `--format hx3` writes/reads a single `.hx3` frame-collection file per
  message instead of QR PNGs, for transports (USB drive, email) where a
  camera isn't the right fit.
- A guardian's round-1 nonces are kept in an encrypted local file next to
  their share (`<share>.qr-nonce` by default, override with
  `--nonce-file`) between `qr-commit` and `qr-share` — this file is local
  device state, never written into `--dir`, and is deleted once `qr-share`
  consumes it.
- `qr-finalize` recovers the exact message that was signed from the
  original request (no need to re-supply `--to`/`--lamports`/`--blockhash`),
  verifies the aggregated signature, and optionally broadcasts it — the
  result is identical to `mpc-sign`'s output.

---

## Verify

Passive integrity check for shard/share files. Never decrypts into the clear
and never touches the access log.

```bash
horcrux verify ./usb/shard-1.hx ./usb/shard-2.hx
horcrux verify ./mpc/mpc-1.hx ./mpc/mpc-2.hx --password guardian
```

Checks

- File magic (`HX1` SSS shard vs `HX2` FROST share) and format version
- Exact file length / sealed-payload bounds
- Metadata (threshold, share count, ids)
- Cross-file consistency (all one kind, one split — mixed types or mixed
  split parameters are reported)
- With `--password`, each file's AES-256-GCM authentication tag

Exits non-zero if any file fails.

---

## Log

View the access log (JSON-lines, append-only).

```bash
horcrux log
horcrux log --tail 10
horcrux log --json
```

Shows

- timestamp (UTC)

- shard id

- outcome: `ok` / `fail` / `blocked` / `signed`

---

## Interactive TUI

A terminal UI covering the Solana-only MVP flows (Mode A and Mode B), for
guardians who would rather navigate menus and forms than memorize flags.

```bash
horcrux tui
```

```
horcrux
└── tui
    ├── Access log        (read-only; color-coded by verdict/entry kind)
    ├── Verify             shard/share files
    ├── Init                — split a key (Mode A)
    ├── Sign                — Mode A, offline or broadcast
    └── MPC split/sign      — Mode B, offline or broadcast
```

Navigation is Tab/Shift+Tab between fields, arrow keys within lists, Space to
toggle a checkbox, Enter to run, Esc to go back. Password fields are always
masked as they're typed. Bitcoin/Cosmos chain selection and the air-gapped QR
flow (`qr-*`) are CLI-only for now; the TUI is Solana Mode A/B, matching the
"ship the MVP first" sequencing the rest of this project follows.

Like `sign`/`mpc-sign`, the Sign and MPC screens run the same audit pre-flight
as the CLI before any key material is touched: a `Warn` verdict shows a modal
you must explicitly continue past, and a `Block` verdict shows a modal you
must explicitly force through (both choices are logged, exactly like
`--force` on the CLI).

No screen ever displays a reconstructed private key or seed — Sign and MPC
Sign go straight from decrypted key to signed output without the key ever
becoming on-screen state. The one exception, matching the CLI's own
behavior, is a freshly **generated** disposable test key on the Init/MPC
Split screens, shown once with an explicit "shown once" label.

---

## Local Web UI

A browser-based alternative to the TUI, for guardians who'd rather fill in a
form than navigate a terminal. Covers the Solana MVP flows — Access log,
Verify, Init, Sign, standalone Reconstruct, MPC split/sign, and the full
air-gapped `qr-request`/`qr-commit`/`qr-package`/`qr-share`/`qr-finalize`
protocol — backed by the same library code as the CLI and TUI. Split forms can
assign each shard/share to a different connected device (for example one USB
drive per guardian) in a single operation.

```bash
horcrux web
horcrux web --port 7420
```

```
HORCRUX web UI (loopback-only, matches the TUI's Solana MVP scope)

  http://127.0.0.1:7420/?token=6f1c...e0a9

Open that URL in a browser on this machine. The token above is required for every
action; anyone or anything that reaches this port without it gets 401. Nothing
beyond 127.0.0.1 can reach this server. Press Ctrl+C to stop.
```

Security model:

- The listener only ever binds `127.0.0.1` — never `0.0.0.0` — so nothing off
  this machine can reach it, matching the project's offline-first posture.
- Every `/api/*` call must carry a random per-run token (printed once at
  startup and pre-filled into the printed URL) in an `X-Horcrux-Token`
  header. A custom header forces a CORS preflight that this server does not
  answer for other origins, so a malicious page cannot forge these requests
  even if it guesses the port.
- The static page itself carries no secrets and is served without the token
  so it can load before it knows the token from its own URL.
- Shard/share paths are read directly from disk on the machine running
  `horcrux web`, exactly like the CLI and TUI — files are never uploaded
  from the browser.
- Exactly like the CLI and TUI: a `Block` audit verdict refuses the
  operation until the request explicitly sets `force` (still logged when
  overridden); a `Warn` verdict proceeds immediately with the warnings
  surfaced in the response.
- No response ever includes a reconstructed private key or seed, with the
  same one exception as the CLI/TUI: a freshly **generated** disposable test
  key on Init/MPC-split, returned once and never persisted.

---

## Access Logging & Anomaly Detection

Every shard decryption attempt is recorded to an **append-only** access log as a
JSON-lines entry:

```json
{"ts":1767225600000,"attempt":12345,"shard_id":1,"kind":"decrypt_ok"}
```

No passwords or key material are ever logged. Before signing (or
reconstructing), the audit layer (src/audit.rs) scores the attempt against the
log and returns a verdict:

| Signal | Effect |
|--------|--------|
| 3+ trailing decrypt failures within the last hour | **Block** |
| Attempt during unusual hours (UTC 00:00–06:00) | Warn |
| Shard combination never used before | Warn |
| Gap since last access has z-score > 3 | Warn |

A **Block** refuses the operation before any key material is handled; the
refused attempt is itself logged. `--force` overrides a block (still logged).

```bash
# normal history -> signing proceeds and is logged
horcrux sign shard-1.hx shard-2.hx --password guardian \
    --to RecipientAddressBase58 --lamports 1000 --blockhash <base58>

# three wrong-password attempts...
horcrux sign shard-1.hx shard-2.hx --password wrong ...
horcrux sign shard-1.hx shard-2.hx --password wrong ...
horcrux sign shard-1.hx shard-2.hx --password wrong ...

# ...then a legitimate attempt is refused before signing
horcrux sign shard-1.hx shard-2.hx --password guardian ...
# access audit blocked the attempt: 3 failed decrypt attempts within the last 3600s
```

### AI anomaly check

`horcrux ai-check` sends the tail of the access log to a free model on
[OpenRouter](https://openrouter.ai/keys) and asks it to flag anything a human
analyst would find suspicious. It is a second, fuzzier opinion alongside the
rule-based scorer above — purely advisory, and it never blocks signing.

Give it an API key with `horcrux ai-setup` (prompts if `--api-key` is
omitted, and saves to a local `.env` file), or export the environment
variable yourself, or set both by hand:

```bash
horcrux ai-setup                                          # prompts for the key, saves to ./.env
horcrux ai-setup --api-key sk-or-... --model meta-llama/llama-3.3-70b-instruct:free
# or:
export OPENROUTER_API_KEY=sk-or-...
```

`.env` (in the current directory or an ancestor) is loaded automatically on
every `horcrux` invocation; a real environment variable always takes
precedence. `horcrux ai-setup` also reminds you to add `.env` to
`.gitignore` if it isn't already, since it holds a secret key.

```bash
horcrux ai-check                  # last 50 entries, default free model
horcrux ai-check --tail 200
horcrux ai-check --model meta-llama/llama-3.3-70b-instruct:free
```

```
AI ANOMALY WARNING [meta-llama/llama-3.3-70b-instruct:free]: three failed decrypts followed by an immediate block, then a successful attempt seconds later
```

#### Automatic background check before every sign/reconstruct

Whenever an API key is configured, `reconstruct`, `sign`, `mpc-sign`,
`qr-commit`, and `qr-share` also fire this same check in the background the
moment the rule-based audit pre-flight runs — concurrently with the actual
decrypt/sign work, so it adds no latency unless the model responds slower
than the signing operation itself. If the model flags the recent history as
anomalous, a warning prints to stderr once the command finishes:

```
AI ANOMALY WARNING [meta-llama/llama-3.3-70b-instruct:free]: three failed decrypts followed by an immediate block, then a successful attempt seconds later
```

With no API key configured, this is skipped entirely — nothing changes for
users who haven't set one up.

---

# Configuration

HORCRUX is configured at the command line; there is no runtime config file.
Key material never leaves shard files, and thresholds/shares are stored inside
each shard's metadata rather than in a separate config.

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `HORCRUX_RPC_URL` | Solana JSON-RPC endpoint | `http://127.0.0.1:8899` |
| `HORCRUX_BTC_RPC_URL` | Bitcoin Core RPC endpoint | `http://127.0.0.1:18443` |
| `HORCRUX_COSMOS_RPC_URL` | Cosmos Tendermint RPC endpoint | `http://127.0.0.1:26657` |
| `HORCRUX_ACCESS_LOG` | Access log path | `./horcrux-access.log` |
| `OPENROUTER_API_KEY` | OpenRouter API key for `ai-check` | none (required for `ai-check`) |
| `HORCRUX_AI_MODEL` | OpenRouter model id for `ai-check` | `meta-llama/llama-3.3-70b-instruct:free` |

## CLI Flags

| Flag | Applies to | Purpose |
|------|------------|---------|
| `--chain` | `sign`, `mpc-split`, `mpc-sign` | `solana` (default) / `bitcoin` / `cosmos` (`mpc-*` rejects `cosmos`) |
| `--threshold` / `--shares` | `init`, `mpc-split` | Threshold / total shares (default 2-of-3) |
| `--password` | all split/sign commands | Shared guardian password (else prompt per shard) |
| `--out-dir` | `init`, `mpc-split` | Where shard files are written |
| `--group-dir` | `mpc-sign` | Directory containing the group public key package |
| `--to` / `--lamports` / `--blockhash` | `sign`, `mpc-sign` (Solana) | Transaction parameters |
| `--utxo` / `--amount-sat` / `--fee-sat` / `--change-address` | `sign`, `mpc-sign` (Bitcoin) | Transaction parameters |
| `--chain-id` / `--account-number` / `--sequence` / `--amount` / `--denom` / `--gas` / `--fee` | `sign` (Cosmos) | Transaction parameters |
| `--broadcast` / `--rpc-url` | `sign`, `mpc-sign` | Submit the signed tx to the network |
| `--rpc-user` / `--rpc-password` | `sign`, `mpc-sign` (Bitcoin) | Bitcoin Core RPC auth |
| `--dir` | `qr-*` | Air-gap transport directory |
| `--format` | `qr-*` | `qr` (PNG images, default) or `hx3` (files) |
| `--nonce-file` | `qr-commit`, `qr-share` | Local round-1 nonce state (defaults next to the share) |
| `--log-file` / `--force` | `sign`, `mpc-sign`, `reconstruct`, `qr-commit`, `qr-share` | Audit log path / override a block |

---

# Cryptographic Design

HORCRUX combines several established cryptographic primitives.

```
Private Key

↓

Shamir Secret Sharing

↓

Independent Shares

↓

Argon2id

↓

AES-256-GCM

↓

USB Storage
```

Every primitive solves one specific security problem.

---

## Shamir Secret Sharing

Purpose

Distribute trust.

Input

```
Private Key
```

Output

```
Share 1

Share 2

Share 3
```

Properties

✔ Information theoretic security

✔ Configurable threshold

✔ Random polynomial generation

✔ Lagrange reconstruction

---

## Argon2id

Purpose

Password hardening.

Transforms

```
Password

↓

Salt

↓

Memory Hard KDF

↓

256-bit Encryption Key
```

Benefits

- GPU resistant

- ASIC resistant

- Memory hard

- Recommended by OWASP

---

## AES-256-GCM

Purpose

Encrypt shard files.

Provides

- Confidentiality

- Integrity

- Authentication

Every encrypted shard contains

```
Salt

Nonce

Ciphertext

Authentication Tag
```

Any modification immediately invalidates the shard.

---

## Zeroization

Sensitive memory is erased immediately after use.

Protected data includes

- decrypted shard

- reconstructed private key

- passwords

- derived AES keys

Memory lifecycle

```
Allocate

↓

Use

↓

Overwrite

↓

Release
```

---

## Ed25519

Used for

- Solana (native Ed25519 signatures)

---

## FROST Threshold Ed25519

Mode B implements threshold signing.

Instead of reconstructing

```
Key

↓

Sign
```

HORCRUX performs

```
Guardian

↓

Partial Signature

↓

Coordinator

↓

Ed25519 Signature
```

Advantages

✔ Key never reconstructed

✔ Standard Ed25519 output

✔ Compatible with Solana signatures

✔ No blockchain modifications

---

# Security Model

HORCRUX follows a layered defense strategy.

```
Physical Security

↓

Password Security

↓

Cryptography

↓

Memory Safety

↓

Behavior Analysis
```

Every layer assumes another layer may eventually fail.

---

## Security Layers

### Layer 1

Guardian separation

No individual possesses the complete key.

---

### Layer 2

USB custody

Physical theft alone cannot recover a shard.

---

### Layer 3

Password protection

Argon2id derived encryption prevents brute-force attacks.

---

### Layer 4

Authenticated encryption

AES-GCM detects tampering automatically.

---

### Layer 5

Threshold cryptography

Multiple guardians must cooperate.

---

### Layer 6

Memory wiping

Private key lifetime is minimized.

---

### Layer 7

Behavior monitoring

AI identifies suspicious activity before signing.

---

# Threat Model

HORCRUX is designed to mitigate

✔ Device theft

✔ Password guessing

✔ Malware stealing shard files

✔ USB duplication

✔ Guardian compromise

✔ Insider attacks

✔ Offline brute force attacks

✔ Key leakage during storage

✔ Memory persistence after signing

✔ Unauthorized recovery attempts

---

HORCRUX does **not** currently protect against

- Compromised operating systems

- Hardware side-channel attacks

- Physical coercion of all guardians

- Nation-state hardware implants

- Quantum attacks

These remain future research areas.

---

# Performance Goals

| Operation | Expected Time |
|------------|--------------|
| Split Key | <100 ms |
| Encrypt Shard | <50 ms |
| Decrypt Shard | <50 ms |
| Reconstruction | <100 ms |
| Mode A Signing | <500 ms |
| MPC Signing | Network dependent |

---

# Design Philosophy

HORCRUX follows several guiding principles.

## Self Custody

Users retain complete ownership of cryptographic material.

---

## Offline First

Internet connectivity should never be a security requirement.

---

## Defense in Depth

Every protection layer assumes another layer may eventually fail.

---

## Open Cryptography

Never invent cryptographic algorithms.

Use audited, peer-reviewed libraries.

---

## Memory Safety

Rust reduces classes of vulnerabilities common in systems programming.

---

# Roadmap

## Current

- CLI
- SSS
- AES Encryption
- USB Storage
- Mode A Signing (Solana, Bitcoin, Cosmos)
- Mode B FROST Signing (Solana, Bitcoin)
- QR-Based Air-Gapped Mode B (Solana)
- Multi-Chain Signing (Solana, Bitcoin, Cosmos)
- Interactive TUI (Solana Mode A/B MVP)
- Logging
- AI Detection

---

## Planned

- Tauri Desktop GUI
- Proactive Secret Refresh
- Cosmos Mode B (needs an audited threshold-ECDSA crate; none exists yet)
- Hardware Wallet Integration
- Hardware Security Module Support
- Secure Firmware Verification

---

# Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
contribution and release workflow.

Recommended workflow

```
Fork Repository

↓

Create Feature Branch

↓

Write Tests

↓

Run Checks Locally

↓

Submit Pull Request

↓

CI Verifies

↓

Merge into main
```

Please ensure

- Code is formatted

- Tests pass

- Documentation updated

- Security considerations explained

### Continuous integration

`main` is protected like a production branch. Every pull request targeting
`main` and every push to `main` runs the [`CI`](.github/workflows/ci.yml)
workflow (`fmt`, `clippy`, `test`, `build-release`, `security-audit`,
`gitleaks`). The aggregate `CI / verify` check is required before any merge, so
code can only reach `main` after it has been verified. Version tags (`v1.0.0`)
trigger the [`Release`](.github/workflows/release.yml) workflow, which builds
and publishes the binary to a GitHub release.

---

# References

The implementation and design are based on established cryptographic research, including:

- Adi Shamir — *How to Share a Secret* (1979)
- Komlo & Goldberg — FROST: Round-Optimal Schnorr Threshold Signatures
- Zcash Foundation — frost-ed25519 (NCC-audited, v3.0.0)
- Park et al. — Cryptocurrency Wallet Security Survey
- Li et al. — Distributed HSM-Based Key Management

For detailed discussion, see the project report included with this repository.

---

# License

This project is released under the MIT License.

See the LICENSE file for details.

---

## Acknowledgements

HORCRUX was developed as a Final Year B.E. Project in Artificial Intelligence & Machine Learning, combining modern cryptography, secure systems programming, and blockchain infrastructure into a unified offline threshold key management platform.

The project demonstrates that enterprise-inspired threshold custody can be achieved using commodity hardware, open-source cryptographic libraries, and memory-safe software without sacrificing user sovereignty.