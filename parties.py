"""Alice, Bob, Mallory and the insecure channel between them.

The channel is simulated in memory: every packet Alice and Bob exchange goes
through `Channel.transmit`, where Mallory (when present) can read, replace or
alter it before it is delivered.
"""

from dataclasses import dataclass, field, replace

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519

import primitives
from output import say, short_hex


# --- Packets on the wire ------------------------------------------------------------

@dataclass(frozen=True)
class KeyPacket:
    """Bob -> Alice: RSA public key and, optionally, its signature."""
    rsa_der: bytes
    signature: bytes | None


@dataclass(frozen=True)
class EnvelopePacket:
    """Alice -> Bob: the AES key encrypted under the RSA public key she received."""
    wrapped_key: bytes


@dataclass(frozen=True)
class MessagePacket:
    """Alice -> Bob: a message encrypted with AES-256-GCM."""
    seq: int
    nonce: bytes
    ciphertext: bytes


# --- Bob ------------------------------------------------------------------------------

class Bob:
    def __init__(self):
        self._rsa = primitives.generate_rsa_keypair()
        self._signing_key = primitives.generate_signing_key()
        self._session_key: bytes | None = None
        self._last_seq = -1
        self.received: list[str] = []
        self.rejected = 0

    @property
    def verify_key(self) -> ed25519.Ed25519PublicKey:
        """Bob's Ed25519 public key.

        Alice must obtain it before the conversation through a trusted path. On
        the web that is the role of a certificate issued by a certificate
        authority.
        """
        return self._signing_key.public_key()

    def announce_key(self, sign: bool) -> KeyPacket:
        rsa_der = primitives.serialize_public_key(self._rsa.public_key())
        say("BOB", f"generated my RSA-2048 key pair; public key fingerprint: {primitives.fingerprint(rsa_der)}")
        signature = None
        if sign:
            signature = primitives.sign_key(self._signing_key, rsa_der)
            say("BOB", f"signed my public key with Ed25519: {short_hex(signature, 16)}")
        return KeyPacket(rsa_der, signature)

    def receive_envelope(self, packet: EnvelopePacket):
        self._session_key = primitives.unwrap_key(self._rsa, packet.wrapped_key)
        say("BOB", "opened the envelope with my RSA private key; I have the session AES key")

    def receive_message(self, packet: MessagePacket) -> bool:
        if packet.seq <= self._last_seq:
            say("BOB", f"REJECTED: sequence number {packet.seq} replayed or out of order")
            self.rejected += 1
            return False
        try:
            text = primitives.decrypt(self._session_key, packet.seq, packet.nonce, packet.ciphertext)
        except InvalidTag:
            say("BOB", "REJECTED: GCM tag mismatch, the message was altered in transit")
            self.rejected += 1
            return False
        self._last_seq = packet.seq
        self.received.append(text)
        say("BOB", f'received: "{text}"')
        return True


# --- Alice ----------------------------------------------------------------------------

class Alice:
    def __init__(self, trusted_bob_key: ed25519.Ed25519PublicKey | None):
        """`trusted_bob_key` is Bob's Ed25519 key, obtained beforehand.

        With None, Alice verifies nothing and accepts whatever public key
        arrives over the channel.
        """
        self._trusted = trusted_bob_key
        self._bob_rsa = None
        self._session_key: bytes | None = None
        self._seq = 0

    def receive_key(self, packet: KeyPacket) -> bool:
        say("ALICE", f"received an RSA public key; fingerprint: {primitives.fingerprint(packet.rsa_der)}")

        if self._trusted is None:
            say("ALICE", "I have no way to check whose key this is; trusting it")
        elif packet.signature is None:
            say("ALICE", "ABORTED: the key arrived unsigned")
            return False
        elif not primitives.verify_key(self._trusted, packet.signature, packet.rsa_der):
            say("ALICE", "ABORTED: signature does not match Bob's key; someone replaced the public key")
            return False
        else:
            say("ALICE", "valid Ed25519 signature: the key really is Bob's")

        self._bob_rsa = primitives.load_public_key(packet.rsa_der)
        return True

    def make_envelope(self) -> EnvelopePacket:
        self._session_key = primitives.generate_session_key()
        say("ALICE", f"generated the session AES-256 key: {short_hex(self._session_key)}")
        wrapped = primitives.wrap_key(self._bob_rsa, self._session_key)
        say("ALICE", "encrypted the AES key with the RSA public key (OAEP) and sent it")
        return EnvelopePacket(wrapped)

    def send(self, text: str) -> MessagePacket:
        nonce, ciphertext = primitives.encrypt(self._session_key, self._seq, text)
        packet = MessagePacket(self._seq, nonce, ciphertext)
        self._seq += 1
        say("ALICE", f'sending: "{text}"')
        return packet


# --- Mallory --------------------------------------------------------------------------

class Mallory:
    """Active attacker sitting on the channel (man-in-the-middle).

    Replaces Bob's public key with her own. Alice then encrypts the AES key for
    Mallory, who opens it, reads and edits the messages, and re-encrypts them
    for Bob under his real public key. Neither of them notices unless the
    public key is signed.
    """

    def __init__(self, replacements: list[tuple[str, str]]):
        self._rsa = primitives.generate_rsa_keypair()
        self._bob_rsa = None
        self._session_key: bytes | None = None
        self._replacements = replacements
        self.read: list[str] = []

    def intercept(self, packet):
        if isinstance(packet, KeyPacket):
            return self._swap_key(packet)
        if isinstance(packet, EnvelopePacket):
            return self._steal_session_key(packet)
        if isinstance(packet, MessagePacket):
            return self._tamper(packet)
        return packet

    def _swap_key(self, packet: KeyPacket) -> KeyPacket:
        self._bob_rsa = primitives.load_public_key(packet.rsa_der)
        mine = primitives.serialize_public_key(self._rsa.public_key())
        say("MALLORY", f"replaced Bob's public key with mine: {primitives.fingerprint(mine)}")
        if packet.signature is not None:
            # Without Bob's Ed25519 private key there is no way to sign the fake
            # key. The best Mallory can do is forward the original signature.
            say("MALLORY", "the key came signed; forwarding the original signature and hoping nobody checks")
        return KeyPacket(mine, packet.signature)

    def _steal_session_key(self, packet: EnvelopePacket) -> EnvelopePacket:
        self._session_key = primitives.unwrap_key(self._rsa, packet.wrapped_key)
        say("MALLORY", f"opened Alice's envelope with my private key; AES key: {short_hex(self._session_key)}")
        say("MALLORY", "re-encrypted the AES key under Bob's real public key and forwarded it")
        return EnvelopePacket(primitives.wrap_key(self._bob_rsa, self._session_key))

    def _tamper(self, packet: MessagePacket) -> MessagePacket:
        text = primitives.decrypt(self._session_key, packet.seq, packet.nonce, packet.ciphertext)
        self.read.append(text)
        say("MALLORY", f'read: "{text}"')
        altered = text
        for old, new in self._replacements:
            altered = altered.replace(old, new)
        if altered != text:
            say("MALLORY", f'changed it to: "{altered}"')
        nonce, ciphertext = primitives.encrypt(self._session_key, packet.seq, altered)
        return MessagePacket(packet.seq, nonce, ciphertext)


# --- Channel --------------------------------------------------------------------------

@dataclass
class Channel:
    """The insecure network between Alice and Bob."""
    mallory: Mallory | None = None
    corrupt: bool = False
    _corrupted: bool = field(default=False, init=False)

    def transmit(self, packet):
        if isinstance(packet, MessagePacket):
            say("CHANNEL", f"seq={packet.seq} nonce={short_hex(packet.nonce)} ciphertext={short_hex(packet.ciphertext)}")
        if self.mallory is not None:
            packet = self.mallory.intercept(packet)
        if self.corrupt and not self._corrupted and isinstance(packet, MessagePacket):
            packet = self._flip_one_bit(packet)
        return packet

    def _flip_one_bit(self, packet: MessagePacket) -> MessagePacket:
        """Flip the least significant bit of the first ciphertext byte, once."""
        self._corrupted = True
        ciphertext = bytes([packet.ciphertext[0] ^ 0x01]) + packet.ciphertext[1:]
        say("CHANNEL", f"1 bit flipped in transit: {short_hex(packet.ciphertext, 4)} -> {short_hex(ciphertext, 4)}")
        return replace(packet, ciphertext=ciphertext)
