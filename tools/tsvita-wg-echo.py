#!/usr/bin/python3
"""Restricted UDP/TCP echo endpoint for PS Vita WireGuard M2 probes."""

import selectors
import socket


UDP_ADDRESS = ("10.77.0.1", 7777)
TCP_ADDRESS = ("10.77.0.1", 7778)
EXPECTED_UDP_CLIENT = ("10.77.0.2", 40000)
EXPECTED_TCP_IP = "10.77.0.2"
EXPECTED_UDP_PAYLOAD = b"TSVITA-M2-ECHO"
EXPECTED_TCP_PAYLOAD = b"TSVITA-M2-TCP"


def main() -> None:
    selector = selectors.DefaultSelector()
    tcp_buffers = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_server, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_server:
        udp_server.bind(UDP_ADDRESS)
        udp_server.setblocking(False)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind(TCP_ADDRESS)
        tcp_server.listen(2)
        tcp_server.setblocking(False)
        selector.register(udp_server, selectors.EVENT_READ, "udp")
        selector.register(tcp_server, selectors.EVENT_READ, "listen")
        while True:
            for key, _ in selector.select():
                if key.data == "udp":
                    payload, client = udp_server.recvfrom(256)
                    if (client == EXPECTED_UDP_CLIENT and
                            payload == EXPECTED_UDP_PAYLOAD):
                        udp_server.sendto(payload, client)
                elif key.data == "listen":
                    connection, client = tcp_server.accept()
                    if client[0] != EXPECTED_TCP_IP:
                        connection.close()
                        continue
                    connection.setblocking(False)
                    tcp_buffers[connection] = bytearray()
                    selector.register(connection, selectors.EVENT_READ, "tcp")
                else:
                    connection = key.fileobj
                    payload = connection.recv(256)
                    if payload:
                        tcp_buffers[connection].extend(payload)
                    buffered = bytes(tcp_buffers[connection])
                    if (payload and EXPECTED_TCP_PAYLOAD.startswith(buffered) and
                            len(buffered) < len(EXPECTED_TCP_PAYLOAD)):
                        continue
                    selector.unregister(connection)
                    tcp_buffers.pop(connection, None)
                    if buffered == EXPECTED_TCP_PAYLOAD:
                        connection.sendall(buffered)
                    connection.close()


if __name__ == "__main__":
    main()
