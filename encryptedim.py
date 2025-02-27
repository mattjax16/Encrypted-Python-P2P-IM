"""
encryptedim.py

Author: Matt Bass
"""

import argparse
import socket
import sys
import select
import signal
from sys import stdin


""" GLOBALS """
client_socket = None
server_socket = None


""" FUNCTIONS"""


def get_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--s", action="store_true")
    group.add_argument("--c", metavar="hostname", type=str)
    args = parser.parse_args()
    return args


def p2p_message_handler(client_sock):
    try:
        while True:
            inputs, _, _ = select.select([stdin, client_sock], [], [])
            for input in inputs:
                if input == client_sock:
                    try:
                        msg = client_sock.recv(2048).decode("utf-8")
                        if not msg:
                            return
                        print(msg, end="")
                    except:
                        return
                else:
                    try:
                        msg = stdin.readline()
                        if not msg:
                            return
                        client_sock.sendall(msg.encode("utf-8"))
                    except:
                        return
    finally:
        client_sock.close()


def server():
    global server_socket
    global client_socket
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(("localhost", 9999))
        server_socket.listen(1)
        client_socket, addr = server_socket.accept()
        p2p_message_handler(client_socket)
    finally:
        pass
        # if client_socket:
        #     client_socket.close()
        # if server_socket:
        #     server_socket.close()


def client(hostname):
    global client_socket
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((hostname, 9999))
        p2p_message_handler(client_socket)
    finally:
        pass
        # if client_socket:
        #     client_socket.close()


def shutdown(signum, frame):
    sys.stdout.flush()

    if client_socket:
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()
    if server_socket:
        server_socket.shutdown(socket.SHUT_RDWR)
        server_socket.close()

    sys.exit(0)
    return


def main():
    args = get_args()
    sys.stdout.flush()

    if args.c:
        client(args.c)
    elif args.s:
        server()

    sys.stdout.flush()


if __name__ == "__main__":
    main()
