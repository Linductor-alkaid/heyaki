#!/usr/bin/env python3
"""M6 TUI service harness driver.

Extends the M4 session flow (local init, discovery, pairing) with the M6
service views: after both TUI instances report an authenticated session over
LAN/direct_host, TUI A sends a peer_acked typed message through the message
view and requires the ACK, TUI B must show the inbound message, and TUI A
must complete a unary RPC (heyaki.tui.echo) through the RPC view with a
structured ok status. Everything runs through the public TUI commands; there
is no private protocol shortcut.
"""
import os
import pty
import re
import select
import subprocess
import sys
import time


class TuiProcess:
    def __init__(self, name, tui_bin, state_dir):
        self.name = name
        self.output = bytearray()
        master, slave = pty.openpty()
        env = os.environ.copy()
        env["TERM"] = "dumb"
        env["XDG_STATE_HOME"] = state_dir
        self.proc = subprocess.Popen(
            [tui_bin, "--profile", "default"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
        )
        os.close(slave)
        self.master = master

    def read_available(self):
        while True:
            ready, _, _ = select.select([self.master], [], [], 0)
            if not ready:
                return
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.output.extend(chunk)

    def wait_for(self, fragment, deadline):
        encoded = fragment.encode() if isinstance(fragment, str) else fragment
        while time.monotonic() < deadline:
            self.read_available()
            if encoded in self.output:
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.02)
        return False

    def send(self, text):
        payload = text.encode() if isinstance(text, str) else text
        os.write(self.master, payload)

    def wait_rendered(self, fragment, deadline):
        encoded = fragment.encode() if isinstance(fragment, str) else fragment
        next_refresh = 0.0
        while time.monotonic() < deadline:
            self.read_available()
            if encoded in self.output:
                return True
            if self.proc.poll() is not None:
                return False
            now = time.monotonic()
            if now >= next_refresh:
                self.send(b"refresh\n")
                next_refresh = now + 0.5
            time.sleep(0.02)
        return False

    def device_id(self):
        match = re.search(rb"LOCAL   ready  device=(hy1_[0-9a-z]+)", self.output)
        return match.group(1).decode() if match else None


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(1)


def main():
    tui_bin = os.environ["HEYAKI_TUI_BIN"]
    state_a = os.environ["HEYAKI_TUI_STATE_A"]
    state_b = os.environ["HEYAKI_TUI_STATE_B"]
    log_path = os.environ.get("HEYAKI_M6_TUI_LOG", "/dev/null")
    password = "correct horse battery staple\n"
    # Loaded runners can spend most of a minute on init+discovery+pairing;
    # the service exchange itself needs real P2P round trips on top.
    deadline = time.monotonic() + 150.0

    peer = TuiProcess("peer", tui_bin, state_b)
    local = TuiProcess("local", tui_bin, state_a)
    processes = [peer, local]
    log = open(log_path, "wb")

    def shutdown():
        for process in processes:
            try:
                process.send(b"quit\n")
            except OSError:
                pass
        for process in processes:
            try:
                process.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.proc.kill()
        for process in processes:
            log.write(b"=== %s ===\n" % process.name.encode())
            log.write(process.output)
        log.close()

    for process in processes:
        if not process.wait_for("command [init|quit]>", deadline):
            shutdown()
            fail("%s: pre-init prompt missing" % process.name)
        process.send("init\n")
        if not process.wait_for("password (minimum", deadline):
            shutdown()
            fail("%s: local initialization prompt missing" % process.name)
        process.send(password)
        if not process.wait_for("confirm password:", deadline):
            shutdown()
            fail("%s: password confirmation prompt missing" % process.name)
        process.send(password)
        if not process.wait_for("command [refresh|relay", deadline):
            shutdown()
            fail("%s: interactive prompt missing after initialization" % process.name)

    for process in processes:
        if not process.wait_rendered("LAN     ready", deadline):
            shutdown()
            sys.stderr.write("no LAN-ready interface for %s\n" % process.name)
            sys.exit(77)

    peer_device = None
    while time.monotonic() < deadline and peer_device is None:
        peer.read_available()
        peer_device = peer.device_id()
        if peer_device is None:
            peer.send(b"refresh\n")
            time.sleep(0.5)
    if peer_device is None:
        shutdown()
        fail("peer device id not reported")

    if not local.wait_rendered("device=%s" % peer_device, deadline):
        shutdown()
        fail("local TUI never listed the peer endpoint")
    endpoint_index = None
    for match in re.finditer(
        r"\[(\d+)\][^\n]*\n      device=%s" % re.escape(peer_device),
        local.output.decode("utf-8", "replace").replace("\r\n", "\n"),
    ):
        endpoint_index = match.group(1)
    if endpoint_index is None:
        shutdown()
        fail("local TUI never listed the peer endpoint")

    local.send("connect %s\n" % endpoint_index)
    if not local.wait_rendered("pairing_restricted", deadline):
        shutdown()
        fail("local TUI session never reached pairing_restricted")

    local.send("pair %s\n" % endpoint_index)
    if not local.wait_for("target authorization password:", deadline):
        shutdown()
        fail("local TUI pairing prompt missing")
    local.send(password)
    if not local.wait_rendered("granted scopes=", deadline):
        shutdown()
        fail("pairing never granted the read-only scopes")

    def session_authenticated(process):
        text = process.output.decode("utf-8", "replace").replace("\r\n", "\n")
        return re.search(
            r"authenticated  stage=authenticated\n"
            r"      device=%s[^\n]*\n"
            r"      endpoint=[^\n]*\n"
            r"      signaling=lan  data=direct_host" % re.escape(peer_device),
            text,
        ) is not None

    local_ok = False
    peer_ok = False
    while time.monotonic() < deadline and not (local_ok and peer_ok):
        local_ok = local_ok or session_authenticated(local)
        peer_ok = peer_ok or re.search(
            rb"authenticated  stage=authenticated", peer.output)
        if local_ok and peer_ok:
            break
        local.send(b"refresh\n")
        peer.send(b"refresh\n")
        time.sleep(0.5)
        for process in processes:
            process.read_available()
    if not local_ok:
        shutdown()
        fail("local TUI session never authenticated over lan/direct_host")
    if not peer_ok:
        shutdown()
        fail("peer TUI never reported the authenticated session")

    # ---- M6: message flow through the public message view (M6-14) ----
    local.send("msg %s\n" % endpoint_index)
    if not local.wait_for("commands [type NAME|", deadline):
        shutdown()
        fail("message view prompt missing")
    local.send("type m6.acceptance\n")
    local.send("ttl 60000\n")
    local.send("mode acked\n")
    local.send("send m6-service-hello\n")
    if not local.wait_for("sent id=", deadline):
        shutdown()
        fail("message view did not report admission")
    # Poll the acks view until the delivery event reaches the acked state:
    # the ACK is a real P2P round trip plus executor dispatch, which can
    # trail the send by seconds on a loaded runner.
    acked = False
    next_poll = 0.0
    while time.monotonic() < deadline:
        local.read_available()
        if re.search(rb"delivery id=\S+ acked", local.output):
            acked = True
            break
        now = time.monotonic()
        if now >= next_poll:
            local.send("acks\n")
            next_poll = now + 2.0
        time.sleep(0.05)
    if not acked:
        shutdown()
        fail("peer_acked message never reached the acked state")
    local.send("exit\n")
    if not local.wait_for("message-view-closed", deadline):
        shutdown()
        fail("message view did not close")

    # The peer TUI must show the typed inbound message (M6-14 rendering).
    if not peer.wait_rendered("m6.acceptance", deadline):
        shutdown()
        fail("peer TUI never displayed the inbound typed message")
    if not peer.wait_rendered("m6-service-hello", deadline):
        shutdown()
        fail("peer TUI never displayed the message payload")

    # ---- M6: unary RPC through the public RPC view (M6-15) ----
    local.send("rpc %s\n" % endpoint_index)
    if not local.wait_for("commands [list|", deadline):
        shutdown()
        fail("rpc view prompt missing")
    local.send("list\n")
    if not local.wait_for("method heyaki.tui.echo", deadline):
        shutdown()
        fail("rpc view did not list the built-in echo method")
    local.send("call heyaki.tui echo m6-rpc-ping\n")
    if not local.wait_for("status=1", deadline):
        shutdown()
        fail("rpc call did not complete with an ok status")
    local.read_available()
    if not re.search(rb"status=1 detail=ok payload=m6-rpc-ping", local.output):
        shutdown()
        fail("rpc echo did not round-trip the payload")

    # Structured failure: an unknown method answers unimplemented (12).
    local.send("call heyaki.tui missing x\n")
    if not local.wait_for("status=12", deadline):
        shutdown()
        fail("unknown method did not answer unimplemented")
    local.send("exit\n")
    if not local.wait_for("rpc-view-closed", deadline):
        shutdown()
        fail("rpc view did not close")

    # The aggregate service diagnostics must show the exchange.
    if not local.wait_rendered("sent_acked=1 acked=1", deadline):
        shutdown()
        fail("service diagnostics did not report the acked send")

    print("M6_TUI_SERVICE_OK index=%s" % endpoint_index)
    shutdown()
    for process in processes:
        if process.proc.returncode not in (0, None):
            fail("%s exited with %d" % (process.name, process.proc.returncode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
