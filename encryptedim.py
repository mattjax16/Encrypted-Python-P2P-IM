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
PORT = 9999
HOST = "0.0.0.0"


""" FUNCTIONS"""

""" FUNCTIONS TO ENCRYPT AND DECRYPT MESSAGES """

def encrypt_message(message, key, iv=None):
    # Convert key to 256-bit key using SHA-256
    key_hash = SHA256.new(data=key.encode('utf-8')).digest()

    if iv is None:
        cipher = AES.new(key_hash, AES.MODE_CBC)
        iv = cipher.iv
    else:
        cipher = AES.new(key_hash, AES.MODE_CBC, iv)

    # Pad and encrypt
    if not isinstance(message, bytes):
        message = message.encode('utf-8')


    padded_data = pad(message, AES.block_size)

    ciphertext = cipher.encrypt(padded_data)


    # Return both ciphertext and IV for decryption
    return ciphertext, iv


def decrypt_message(ciphertext, key, iv):
    try:
        # Convert key to 256-bit key using SHA-256
        key_hash = SHA256.new(data=key.encode('utf-8')).digest()


        # Recreate cipher with same IV
        cipher = AES.new(key_hash, AES.MODE_CBC, iv)

        # Decrypt and unpad
        padded_data = cipher.decrypt(ciphertext)

        data = unpad(padded_data, AES.block_size)


        # Convert to string
        return data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

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
    # Then send the length of the message encrypted than hmac'd
    len_bytes = len(cipher_text).to_bytes(4, byteorder='big')

    encrypted_length, _ = encrypt_message(len_bytes, K1, iv)
    len_hmac = hmac_message((iv + encrypted_length),K2)
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

    iv = client_socket.recv(16)
    if not iv or len(iv) != 16:
        return None

    # Receiving the length of the message and the hmac
    length_iv_bytes = client_socket.recv(48)
    msg_length = length_iv_bytes[:16]
    length_hmac = length_iv_bytes[16:]
    calculated_len_hmac = hmac_message((iv + msg_length), K2)
    if length_hmac != calculated_len_hmac:
        return None
    msg_bytes = decrypt_message(msg_length, K1, iv)
    msg_length = int.from_bytes(msg_bytes.encode(), byteorder='big')

    # Receiving the message and the hmac
    msg_bytes = client_socket.recv(msg_length+32)
    msg = msg_bytes[:msg_length]
    msg_hmac = msg_bytes[msg_length:]
    calculated_msg_hmac = hmac_message(msg, K2)
    if msg_hmac != calculated_msg_hmac:
        return None
    msg = decrypt_message(msg, K1, iv)
    return msg


""" FUNCTIONS TO RUN SERVER AND CLIENT """
def get_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
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
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        client_socket, addr = server_socket.accept()
        p2p_message_handler(client_socket, args.confkey, args.authkey)
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
        client_socket.connect((hostname, PORT))
        p2p_message_handler(client_socket, args.confkey, args.authkey)
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
        client(args)
    elif args.s:
        server(args)

    sys.stdout.flush()


if __name__ == "__main__":
    main()
