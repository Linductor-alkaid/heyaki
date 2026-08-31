#!/usr/bin/env python3
import os
import pty
import select
import subprocess
import sys
import time


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(1)


def main():
    tui_bin = os.environ["HEYAKI_TUI_BIN"]
    relay_url = os.environ["HEYAKI_RELAY_URL"]
    tenant = os.environ["HEYAKI_TENANT"]
    token = os.environ["HEYAKI_TOKEN"]
    log_path = os.environ.get("HEYAKI_TUI_DRIVE_LOG", "/dev/null")
    timeout = 35.0

    master, slave = pty.openpty()
    env = os.environ.copy()
    env["TERM"] = "dumb"
    proc = subprocess.Popen(
        [tui_bin, "--profile", "default"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    started = time.monotonic()

    def read_available():
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if not ready:
                return
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            output.extend(chunk)

    def wait_for(fragment, deadline):
        while time.monotonic() < deadline:
            read_available()
            if fragment in output:
                return True
            if proc.poll() is not None:
                return False
            time.sleep(0.02)
        return False

    def send(text):
        payload = text if isinstance(text, bytes) else text.encode()
        os.write(master, payload)

    steps = [
        ("command [refresh|relay", b"relay\n"),
        ("relay URL", (relay_url + "\n").encode()),
        ("tenant [default]", (tenant + "\n").encode()),
        ("bootstrap token:", (token + "\n").encode()),
        ("command [refresh|relay", b"quit\n"),
    ]
    deadline = time.monotonic() + timeout
    for fragment, text in steps:
        if not wait_for(fragment.encode(), deadline):
            break
        if time.monotonic() >= deadline:
            break
        send(text)

    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        with open(log_path, "wb") as log:
            log.write(bytes(output))
        fail("TUI driver timed out")
    finally:
        read_available()
        os.close(master)

    with open(log_path, "wb") as log:
        log.write(bytes(output))
    if proc.returncode != 0:
        fail(f"TUI exited with status {proc.returncode}")


if __name__ == "__main__":
    main()
