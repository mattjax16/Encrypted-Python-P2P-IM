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
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode



""" GLOBALS """
client_socket = None
server_socket = None


""" FUNCTIONS"""

""" FUNCTIONS TO ENCRYPT AND DECRYPT MESSAGES """
def encrypt_message(message, K1):

    # hashing k1 so that its 256 bits
    K1 = SHA256.new(data = K1.encode('utf-8')).digest()
    cipher = AES.new(K1, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher_text, cipher.iv

def decrypt_message(cipehr_text, iv ,K1):
    K1 = SHA256.new(data=K1.encode('utf-8')).digest()
    cipher = AES.new(K1, AES.MODE_CBC, iv)
    msg = cipher.decrypt(cipehr_text).decode('utf-8')
    return msg

def hmac_message(message, K2):
    K2 = SHA256.new(data=K2.encode('utf-8')).digest()
    if isinstance(message, bytes):
        mac = SHA256.new(data=message + K2).digest()
    else:
        mac = SHA256.new(data=(message.encode('utf-8') + K2)).digest()
    return mac


def send_encrypted_message(message, K1, K2):

    # First send the IV
    cipher_text, iv = encrypt_message(message, K1)

    # Then send the length of the message encrypted than hmac'd
    len_str = str(len(cipher_text))
    encrypted_length, _ = encrypt_message(len_str, K1)
    len_hmac = hmac_message((iv + encrypted_length),K2).decode('utf-8')
    len_payload = encrypted_length + len_hmac



    # Then send the message HMACk2(iv + Ek1(len(m))) + Ek1(m)+HMACk2(Ek1(m))
    msg_mac = hmac_message(cipher_text, K2)
    msg_payload = cipher_text + msg_mac



    # Sending all the parts of the message
    client_socket.sendall(iv)
    client_socket.sendall(len_payload)
    client_socket.sendall(msg_payload)

    return


def receive_encrypted_message(K1, K2):

    iv = socket.recv(16)
    if not iv or len(iv) != 16:
        return None

    # Receiving the length of the message and the hmac
    length_iv_bytes = socket.recv(20)
    msg_length = length_iv_bytes[:4]
    length_hmac = length_iv_bytes[4:]
    calculated_len_hmac = hmac_message((iv + msg_length), K2)
    if length_hmac != calculated_len_hmac:
        return None
    msg_length = decrypt_message(msg_length, iv, K1)
    msg_length = int(msg_length)

    # Receiving the message and the hmac
    msg_bytes = socket.recv(msg_length+16)
    msg = msg_bytes[:msg_length]
    msg_hmac = msg_bytes[msg_length:]
    calculated_msg_hmac = hmac_message(msg, K2)
    if msg_hmac != calculated_msg_hmac:
        return None
    msg = decrypt_message(msg, iv, K1)
    return msg


""" FUNCTIONS TO RUN SERVER AND CLIENT """
def get_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--debug", type=bool)
    group.add_argument("--s", action="store_true")
    group.add_argument("--c", metavar="hostname", type=str)
    parser.add_argument("--confkey", metavar="K1", type=str, required=True)
    parser.add_argument("--authkey", metavar="K2", type=str, required=True)
    args = parser.parse_args()
    return args


def p2p_message_handler(client_sock,K1,K2):
    try:
        while True:
            inputs, _, _ = select.select([stdin, client_sock], [], [])
            for input in inputs:

                # Receiving message
                if input == client_sock:
                    try:
                        msg = receive_encrypted_message(K1, K2)
                        if not msg:
                            return
                        print(msg, end="")
                    except:
                        return

                # Sending message
                else:
                    try:
                        msg = stdin.readline()
                        if not msg:
                            return
                        send_encrypted_message(msg, K1, K2)
                    except:
                        return
    finally:
        client_sock.close()


def server(args):
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


def client(args):
    global client_socket
    hostname = args.c
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


def debug(args):
    print("Debugging")
    sys.stdout.flush()

    K1 = args.confkey
    K2 = args.authkey

    msg = "Hello, World!"

    print("Message: ", msg)

    cypehr_text, iv = encrypt_message(msg, K1 )

    decyphr = decrypt_message(cypehr_text, iv ,K1)
    print("Decrypted Message: ", decyphr)

    return

def main():
    args = get_args()
    sys.stdout.flush()

    if args.debug:
        debug(args)

    if args.c:
        client(args)
    elif args.s:
        server(args)

    sys.stdout.flush()


if __name__ == "__main__":
    main()
