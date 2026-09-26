"""End-to-end checks of the four presentation scenarios."""

import pytest

import demo
import output
from parties import Alice, Bob, Channel, MessagePacket

MESSAGES = demo.DEFAULT_MESSAGES
TAMPERED = [m.replace("12345-6", "99999-9") for m in MESSAGES]


@pytest.fixture(autouse=True)
def quiet():
    output.configure(quiet=True)
    yield
    output.configure(quiet=False)


@pytest.mark.parametrize("sign", [False, True])
def test_normal_conversation_delivers_every_message(sign):
    result = demo.run(sign=sign)
    assert result.handshake_ok
    assert result.bob_received == MESSAGES
    assert result.bob_rejected == 0
    assert result.mallory_read == []


def test_corrupted_bit_is_rejected_and_the_rest_gets_through():
    result = demo.run(corrupt=True)
    assert result.bob_rejected == 1
    assert result.bob_received == MESSAGES[1:]


def test_mitm_without_signature_reads_and_alters_everything():
    result = demo.run(mitm=True)
    assert result.handshake_ok
    assert result.mallory_read == MESSAGES
    assert result.bob_received == TAMPERED
    assert result.bob_rejected == 0


def test_mitm_with_signature_is_detected_before_any_message():
    result = demo.run(mitm=True, sign=True)
    assert not result.handshake_ok
    assert result.mallory_read == []
    assert result.bob_received == []


def test_custom_messages_and_replacements():
    result = demo.run(mitm=True, messages=["pay 10"], replacements=[("10", "1000")])
    assert result.mallory_read == ["pay 10"]
    assert result.bob_received == ["pay 1000"]


def test_alice_rejects_an_unsigned_key_when_she_expects_a_signature():
    bob = Bob()
    alice = Alice(trusted_bob_key=bob.verify_key)
    assert not alice.receive_key(bob.announce_key(sign=False))


def test_bob_rejects_a_replayed_message():
    bob, alice = Bob(), Alice(trusted_bob_key=None)
    channel = Channel()
    alice.receive_key(channel.transmit(bob.announce_key(sign=False)))
    bob.receive_envelope(channel.transmit(alice.make_envelope()))
    packet = alice.send("once only")
    assert bob.receive_message(packet)
    assert not bob.receive_message(packet)
    assert bob.received == ["once only"]
    assert bob.rejected == 1


def test_bob_rejects_a_message_whose_sequence_number_was_changed():
    bob, alice = Bob(), Alice(trusted_bob_key=None)
    alice.receive_key(bob.announce_key(sign=False))
    bob.receive_envelope(alice.make_envelope())
    packet = alice.send("hello")
    forged = MessagePacket(packet.seq + 5, packet.nonce, packet.ciphertext)
    assert not bob.receive_message(forged)


def test_cli_runs_every_scenario(capsys):
    output.configure(quiet=False, color=False)
    for flags in ([], ["--corrupt"], ["--mitm"], ["--mitm", "--sign"]):
        demo.main(flags)
    out = capsys.readouterr().out
    assert "GCM tag mismatch" in out
    assert 'changed it to: "Please transfer $500 to account 99999-9."' in out
    assert "ABORTED: signature does not match" in out
