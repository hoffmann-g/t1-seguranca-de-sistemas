# Hybrid encryption and the man-in-the-middle attack

Practical assignment (TP1) for Segurança de Sistemas, PUCRS, 2026/2.

Alice sends messages to Bob over an insecure channel. The program shows, step by step:

1. how symmetric and asymmetric encryption are combined (the scheme TLS uses);
2. that AES-GCM detects any change to a message in transit;
3. how an attacker in the middle (Mallory) reads and alters every message when the public key is not authenticated;
4. how a digital signature over the public key exposes that attack.

## Mechanisms

| Purpose | Algorithm | Where |
|---|---|---|
| Encrypt messages (confidentiality + integrity) | AES-256-GCM, random 96-bit nonce, sequence number as associated data | `primitives.encrypt` |
| Deliver the AES session key | RSA-2048 with OAEP (SHA-256) | `primitives.wrap_key` |
| Authenticate Bob's RSA public key | Ed25519 signature | `primitives.sign_key` |

All primitives come from the [`cryptography`](https://cryptography.io) library.

## Protocol

```
Bob                          channel (Mallory?)                     Alice
 |-- RSA public key [+ Ed25519 signature] ------------------------->|  Alice checks the signature
 |<------------------------------ RSA-OAEP(AES session key) --------|
 |<------------------------------ AES-GCM(message), seq, nonce -----|
```

With `--mitm`, Mallory replaces Bob's RSA key with her own. Alice encrypts the session key for Mallory, who
opens it, re-encrypts it for Bob, and from then on decrypts, edits and re-encrypts every message. Nothing in
the ciphertexts reveals the attack.

With `--sign`, Alice already holds Bob's Ed25519 public key, obtained beforehand through a trusted path (on the
web this is the certificate signed by a certificate authority). Mallory cannot sign her own key as Bob, so
Alice aborts before sending anything.

## Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/) (recommended), or `pip`

## Running

```sh
uv run demo.py                  # 1. normal encrypted conversation
uv run demo.py --corrupt        # 2. one bit flipped in transit; Bob rejects the message
uv run demo.py --mitm           # 3. Mallory reads everything and changes the account number
uv run demo.py --mitm --sign    # 4. the signature exposes the attack; Alice aborts
```

`uv run` creates the virtual environment and installs the dependencies on first use. Without uv:

```sh
python -m venv .venv
source .venv/bin/activate
pip install cryptography
python demo.py --mitm
```

### Graphical interface

```sh
uv run gui.py
```

The window shows Alice, Bob and Mallory on a diagram, animates each packet along the channel and lists the keys
each party holds as it acquires them (the RSA key Alice receives is colored by its real owner, so a swapped key
shows up in red). Press `1`–`4` to run the four scenarios, or set the switches on the left and press Enter.

On Linux, the Python builds that uv downloads ship a Tk without font rendering, so the window falls back to a
bitmap font. Install the system Tk and run the GUI with the system Python instead:

```sh
sudo pacman -S tk                 # Arch; Debian/Ubuntu: sudo apt install python3-tk
uv run --python /usr/bin/python3 gui.py
```

Windows and macOS need nothing extra.

### Options

| Option | Effect |
|---|---|
| `--mitm` | put Mallory in the channel |
| `--sign` | Bob signs his RSA public key and Alice verifies it |
| `--corrupt` | flip one bit of the first message's ciphertext |
| `-m TEXT`, `--message TEXT` | message to send; repeat for several (replaces the default ones) |
| `--replace OLD NEW` | text Mallory swaps in the messages; repeatable (default `12345-6` → `99999-9`) |
| `--delay SECONDS` | pause after each line, for live presentations |
| `--no-color` | plain output |

Example:

```sh
uv run demo.py --mitm -m "meet at 8pm" --replace 8pm 11pm --delay 0.5
```

## Tests

```sh
uv run pytest
```

The tests cover the primitives (round trips, OAEP randomization, tag checks on any flipped bit, signature binding)
and the four scenarios end to end.

## Files

| File | Contents |
|---|---|
| `demo.py` | command line and scenario runner |
| `gui.py` | Tkinter interface with the animated diagram |
| `parties.py` | Alice, Bob, Mallory, the channel and the packets they exchange |
| `primitives.py` | cryptographic operations and their parameters |
| `output.py` | colored narration |
| `tests/` | pytest suite |

## Limitations

- The channel is simulated in memory, so the demo does not depend on the network during the presentation.
- Bob's signature covers only his RSA key. A real protocol (TLS 1.3) signs the whole handshake, including fresh
  random values from both sides, so an old signed key cannot be replayed.
- RSA key transport has no forward secrecy: whoever later obtains Bob's RSA private key can decrypt recorded
  sessions. TLS 1.3 uses ephemeral Diffie-Hellman instead.
