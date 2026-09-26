"""Hybrid encryption demo: Alice talks to Bob while Mallory sits in the middle.

    uv run demo.py                    # normal encrypted conversation
    uv run demo.py --corrupt          # 1 bit flipped in transit, GCM catches it
    uv run demo.py --mitm             # Mallory swaps the keys, reads and edits everything
    uv run demo.py --mitm --sign      # Bob's signature exposes the attack
"""

import argparse
from dataclasses import dataclass

import output
from output import heading, say
from parties import Alice, Bob, Channel, Mallory

DEFAULT_MESSAGES = [
    "Hi Bob, it's Alice.",
    "Please transfer $500 to account 12345-6.",
]
DEFAULT_REPLACEMENTS = [("12345-6", "99999-9")]


@dataclass
class Result:
    handshake_ok: bool
    bob_received: list[str]
    bob_rejected: int
    mallory_read: list[str]


def run(
    mitm: bool = False,
    sign: bool = False,
    corrupt: bool = False,
    messages: list[str] = DEFAULT_MESSAGES,
    replacements: list[tuple[str, str]] = DEFAULT_REPLACEMENTS,
) -> Result:
    bob = Bob()
    # With --sign, Alice already holds Bob's Ed25519 key (obtained out of band,
    # the way a browser ships with trusted CA certificates).
    alice = Alice(trusted_bob_key=bob.verify_key if sign else None)
    mallory = Mallory(replacements) if mitm else None
    channel = Channel(mallory=mallory, corrupt=corrupt)

    heading("1. Bob publishes his RSA public key")
    handshake_ok = alice.receive_key(channel.transmit(bob.announce_key(sign)))

    if handshake_ok:
        heading("2. Alice sends Bob the session key")
        bob.receive_envelope(channel.transmit(alice.make_envelope()))

        heading("3. Encrypted messages")
        for text in messages:
            bob.receive_message(channel.transmit(alice.send(text)))

    result = Result(
        handshake_ok=handshake_ok,
        bob_received=list(bob.received),
        bob_rejected=bob.rejected,
        mallory_read=list(mallory.read) if mallory else [],
    )
    _summarize(result, messages, mitm)
    return result


def _summarize(result: Result, sent: list[str], mitm: bool):
    heading("Summary")
    if not result.handshake_ok:
        say("ALICE", "conversation aborted before any message was sent; Mallory learned nothing")
        return
    if mitm:
        say("MALLORY", f"read {len(result.mallory_read)} of {len(sent)} messages")
        if result.bob_received != sent:
            say("BOB", "what I received is not what Alice sent, and I have no way to tell")
    if result.bob_rejected:
        say("BOB", f"rejected {result.bob_rejected} tampered message(s)")
    if not mitm and not result.bob_rejected:
        say("BOB", "every message arrived intact and only Alice and I could read it")


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Hybrid encryption (AES-256-GCM + RSA-2048-OAEP) with an optional man-in-the-middle.",
    )
    parser.add_argument("--mitm", action="store_true", help="put Mallory in the middle of the channel")
    parser.add_argument("--sign", action="store_true", help="Bob signs his RSA public key with Ed25519 and Alice verifies it")
    parser.add_argument("--corrupt", action="store_true", help="flip one bit of the first message in transit")
    parser.add_argument("--message", "-m", action="append", help="message to send (repeatable; replaces the default ones)")
    parser.add_argument(
        "--replace", nargs=2, action="append", metavar=("OLD", "NEW"),
        help="text Mallory replaces in the messages (repeatable; default: 12345-6 -> 99999-9)",
    )
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to wait after each line, for live presentations")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args(argv)

    output.configure(delay=args.delay, color=False if args.no_color else None)
    run(
        mitm=args.mitm,
        sign=args.sign,
        corrupt=args.corrupt,
        messages=args.message or DEFAULT_MESSAGES,
        replacements=[tuple(r) for r in args.replace] if args.replace else DEFAULT_REPLACEMENTS,
    )


if __name__ == "__main__":
    main()
