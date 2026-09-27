"""GUI checks. Skipped when there is no display (e.g. CI)."""

import os
import time

import pytest

tk = pytest.importorskip("tkinter")

import demo
import gui
import output

pytestmark = pytest.mark.skipif(
    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    reason="no display available",
)


@pytest.fixture
def app():
    output.configure(quiet=False)
    root = tk.Tk()
    root.withdraw()
    application = gui.App(root, animate=False)
    yield application
    application.close()
    output.configure()


def wait_until_done(app: gui.App, timeout: float = 20.0):
    deadline = time.monotonic() + timeout
    while app.running:
        assert time.monotonic() < deadline, "scenario did not finish"
        app.root.update()
        time.sleep(0.01)
    app.root.update()


@pytest.mark.parametrize(
    "preset, style",
    [(0, "ok"), (1, "detected"), (2, "attack"), (3, "blocked")],
)
def test_presets_reach_the_expected_verdict(app, preset, style):
    app.run_preset(preset)
    wait_until_done(app)
    assert app.last_verdict[0] == style


def test_log_shows_every_party_in_the_mitm_scenario(app):
    app.run_preset(2)
    wait_until_done(app)
    log = app.log.get("1.0", tk.END)
    for party in ("ALICE", "BOB", "MALLORY", "CHANNEL"):
        assert party in log
    assert "changed it to" in log


def test_custom_messages_and_replacement(app):
    app.messages.delete("1.0", tk.END)
    app.messages.insert("1.0", "meet at 8pm")
    app.old_text.set("8pm")
    app.new_text.set("11pm")
    app.mitm.set(True)
    app.run()
    wait_until_done(app)
    assert 'received: "meet at 11pm"' in app.log.get("1.0", tk.END)


def test_key_chips_show_the_stolen_session_key(app):
    app.run_preset(2)
    wait_until_done(app)
    mallory_chips = [chip.text for chip in app.state.chips["MALLORY"]]
    assert "Alice's AES key (stolen)" in mallory_chips
    alice_key = next(chip for chip in app.state.chips["ALICE"] if chip.text.startswith("RSA public key"))
    assert alice_key.color == gui.PARTY_COLORS["MALLORY"]


def test_signed_mitm_marks_alice_as_aborted(app):
    app.run_preset(3)
    wait_until_done(app)
    assert app.state.status["ALICE"].startswith("ABORTED")
    assert "Alice's AES key (stolen)" not in [chip.text for chip in app.state.chips["MALLORY"]]


def test_toggling_an_option_deselects_the_preset_card(app):
    app.run_preset(0)
    wait_until_done(app)
    assert app.cards[0].selected
    app.corrupt.set(True)
    assert not any(card.selected for card in app.cards)


def test_empty_message_box_does_not_start_a_run(app):
    app.messages.delete("1.0", tk.END)
    app.run()
    assert not app.running


def test_verdict_without_mitm_or_tampering_is_ok():
    result = demo.Result(handshake_ok=True, bob_received=["a"], bob_rejected=0, mallory_read=[])
    assert gui.verdict(result, mitm=False, sent=["a"])[0] == "ok"
