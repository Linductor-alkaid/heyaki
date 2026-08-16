#!/usr/bin/env python3
import selectors
import socket
import sys


def main():
    listen_host = sys.argv[1]
    listen_port = int(sys.argv[2])
    target_host = sys.argv[3]
    target_port = int(sys.argv[4])
    capture_path = sys.argv[5]

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_host, listen_port))
    listener.listen(16)
    actual_port = listener.getsockname()[1]
    print(f"PROXY_PORT={actual_port}", flush=True)
    if listen_port == 0:
        listen_port = actual_port

    selector = selectors.DefaultSelector()
    capture = open(capture_path, "wb", buffering=0)
    active = True

    def close_pair(client, upstream):
        try:
            selector.unregister(client)
        except Exception:
            pass
        try:
            selector.unregister(upstream)
        except Exception:
            pass
        try:
            client.close()
        except OSError:
            pass
        try:
            upstream.close()
        except OSError:
            pass

    def on_readable(conn, other):
        try:
            data = conn.recv(65536)
        except OSError:
            data = b""
        if not data:
            close_pair(conn, other)
            return
        capture.write(data)
        try:
            other.sendall(data)
        except OSError:
            close_pair(conn, other)

    listener.setblocking(False)
    selector.register(listener, selectors.EVENT_READ, ("accept", None))

    try:
        while active:
            events = selector.select(timeout=0.2)
            for key, _ in events:
                conn, other = key.data
                if conn == "accept":
                    client, _ = listener.accept()
                    client.setblocking(False)
                    upstream = socket.create_connection((target_host, target_port))
                    upstream.setblocking(False)
                    selector.register(client, selectors.EVENT_READ, (client, upstream))
                    selector.register(upstream, selectors.EVENT_READ, (upstream, client))
                else:
                    on_readable(conn, other)
    except KeyboardInterrupt:
        pass
    finally:
        selector.close()
        listener.close()
        capture.close()


if __name__ == "__main__":
    main()
