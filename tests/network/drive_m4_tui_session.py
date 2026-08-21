#!/usr/bin/env python3
"""M4 TUI session harness driver.

Spawns two heyaki-tui instances with independent local profiles, completes
local initialization for both over a pty, waits until they discover each other
on the LAN, selects the discovered endpoint from TUI A's merged endpoint list,
and requires both processes to report an authenticated session over the LAN
signaling route with a direct-host data path.
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
        """Wait for a rendered fragment, refreshing the view periodically.

        The TUI repaints only after a command, so passively reading the pty
        would stall on the first frame.
        """
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
    log_path = os.environ.get("HEYAKI_TUI_SESSION_LOG", "/dev/null")
    password = "correct horse battery staple\n"
    deadline = time.monotonic() + 75.0

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

    # Complete local initialization for both instances: fresh profiles first
    # show a pre-init menu before asking for the authorization password.
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

    # Both nodes must reach LAN readiness; without a multicast-capable
    # interface the harness skips rather than pretending to test selection.
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

    # Wait until the local TUI lists the peer in its merged endpoint view.
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

    print("M4_TUI_SESSION_OK index=%s" % endpoint_index)
    shutdown()
    for process in processes:
        if process.proc.returncode not in (0, None):
            fail("%s exited with %d" % (process.name, process.proc.returncode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
