"""Identifiable TCP/UDP echo application for disposable acceptance guests."""
import selectors
import socket


def serve():
    selector = selectors.DefaultSelector()
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(('0.0.0.0', 2096))
    tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('0.0.0.0', 2096))
    selector.register(tcp, selectors.EVENT_READ)
    selector.register(udp, selectors.EVENT_READ)
    try:
        while True:
            for key, _ in selector.select():
                if key.fileobj is tcp:
                    connection, _ = tcp.accept()
                    with connection:
                        connection.settimeout(5)
                        data = bytearray()
                        while chunk := connection.recv(2048):
                            data.extend(chunk)
                            if len(data) > 2048:
                                raise ValueError('Acceptance payload exceeded its bound')
                        connection.sendall(b'gre4-acceptance:' + data)
                else:
                    data, peer = udp.recvfrom(2048)
                    udp.sendto(b'gre4-acceptance:' + data, peer)
    finally:
        selector.close()
        tcp.close()
        udp.close()


if __name__ == '__main__':
    serve()
