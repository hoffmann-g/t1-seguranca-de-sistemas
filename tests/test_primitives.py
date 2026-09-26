import pytest
from cryptography.exceptions import InvalidTag

import primitives


@pytest.fixture(scope="module")
def rsa_key():
    return primitives.generate_rsa_keypair()


def test_rsa_key_is_2048_bits(rsa_key):
    assert rsa_key.key_size == 2048


def test_wrap_and_unwrap_round_trip(rsa_key):
    session_key = primitives.generate_session_key()
    wrapped = primitives.wrap_key(rsa_key.public_key(), session_key)
    assert wrapped != session_key
    assert primitives.unwrap_key(rsa_key, wrapped) == session_key


def test_oaep_is_randomized(rsa_key):
    session_key = primitives.generate_session_key()
    a = primitives.wrap_key(rsa_key.public_key(), session_key)
    b = primitives.wrap_key(rsa_key.public_key(), session_key)
    assert a != b


def test_unwrap_with_wrong_key_fails(rsa_key):
    other = primitives.generate_rsa_keypair()
    wrapped = primitives.wrap_key(rsa_key.public_key(), primitives.generate_session_key())
    with pytest.raises(ValueError):
        primitives.unwrap_key(other, wrapped)


def test_public_key_serialization_round_trip(rsa_key):
    der = primitives.serialize_public_key(rsa_key.public_key())
    loaded = primitives.load_public_key(der)
    assert primitives.serialize_public_key(loaded) == der


def test_session_key_is_256_bits():
    assert len(primitives.generate_session_key()) == 32


def test_encrypt_decrypt_round_trip():
    key = primitives.generate_session_key()
    nonce, ciphertext = primitives.encrypt(key, 0, "attack at dawn")
    assert len(nonce) == 12
    assert b"attack at dawn" not in ciphertext
    assert primitives.decrypt(key, 0, nonce, ciphertext) == "attack at dawn"


def test_every_message_gets_a_fresh_nonce():
    key = primitives.generate_session_key()
    nonces = {primitives.encrypt(key, 0, "same text")[0] for _ in range(100)}
    assert len(nonces) == 100


def test_ciphertext_carries_a_16_byte_tag():
    key = primitives.generate_session_key()
    _, ciphertext = primitives.encrypt(key, 0, "abc")
    assert len(ciphertext) == len("abc") + 16


@pytest.mark.parametrize("position", [0, 5, -1])
def test_flipping_any_bit_breaks_the_tag(position):
    key = primitives.generate_session_key()
    nonce, ciphertext = primitives.encrypt(key, 0, "hello")
    tampered = bytearray(ciphertext)
    tampered[position] ^= 0x01
    with pytest.raises(InvalidTag):
        primitives.decrypt(key, 0, nonce, bytes(tampered))


def test_sequence_number_is_authenticated():
    key = primitives.generate_session_key()
    nonce, ciphertext = primitives.encrypt(key, 3, "hello")
    with pytest.raises(InvalidTag):
        primitives.decrypt(key, 4, nonce, ciphertext)


def test_wrong_key_fails_to_decrypt():
    nonce, ciphertext = primitives.encrypt(primitives.generate_session_key(), 0, "hello")
    with pytest.raises(InvalidTag):
        primitives.decrypt(primitives.generate_session_key(), 0, nonce, ciphertext)


def test_signature_verifies_for_the_signed_key(rsa_key):
    signing_key = primitives.generate_signing_key()
    der = primitives.serialize_public_key(rsa_key.public_key())
    signature = primitives.sign_key(signing_key, der)
    assert primitives.verify_key(signing_key.public_key(), signature, der)


def test_signature_does_not_transfer_to_another_key(rsa_key):
    signing_key = primitives.generate_signing_key()
    der = primitives.serialize_public_key(rsa_key.public_key())
    other_der = primitives.serialize_public_key(primitives.generate_rsa_keypair().public_key())
    signature = primitives.sign_key(signing_key, der)
    assert not primitives.verify_key(signing_key.public_key(), signature, other_der)


def test_signature_from_another_signer_is_rejected(rsa_key):
    der = primitives.serialize_public_key(rsa_key.public_key())
    signature = primitives.sign_key(primitives.generate_signing_key(), der)
    assert not primitives.verify_key(primitives.generate_signing_key().public_key(), signature, der)


def test_signature_is_bound_to_the_context(rsa_key):
    signing_key = primitives.generate_signing_key()
    der = primitives.serialize_public_key(rsa_key.public_key())
    bare_signature = signing_key.sign(der)
    assert not primitives.verify_key(signing_key.public_key(), bare_signature, der)


def test_fingerprint_format():
    fp = primitives.fingerprint(b"abc")
    assert fp == "ba:78:16:bf:8f:01:cf:ea"
