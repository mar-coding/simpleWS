import binascii
import hashlib
import re
import secrets
import socket
from hashlib import sha3_512
from signal import SIG_DFL, SIGPIPE, signal
from threading import Thread
import my_encryption as enc

from tinyec import registry

signal(SIGPIPE,SIG_DFL)

# global variables
HOST = '127.0.0.1'
PORT = 61001
CPUB_KEY = ""
SPUB_KEY = ""
SPR_KEY = ""
NAME = "server"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #1
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def main():
    s.bind((HOST, PORT)) #2
    s.listen(8) #3
    print(f'Server running on port {PORT}')

    while True:
        try:
            client, address = s.accept() #4
            print(f'{address} was connected.')
            Thread(target=server_handler, args=(client,)).start()
        except Exception:
            break

# for each client this function keeps running on a thread so we will get the messages they send
def server_handler(client_socket: socket.socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            print(message)
        except OSError:
            break
        message = b"Hi back!"
        client_socket.send(message)

def server_program():
    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((HOST, PORT))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(1)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        # msg = "sch -pub:{} -name:{} -testMsg:{} -hash:{}".format(SPUB_KEY,NAME,"",)
        msg = "sch -pub:{} -name:{}".format("135sdfg2","Amin")
        hash_msg = hashlib.sha3_512(msg.encode('utf-8'))
        msg ="".join([msg," -hash:{}".format(hash_msg.hexdigest())])
        print(msg)
        conn.send(f'sch pub:',)
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))
        data = input(' -> ')
        conn.send(data.encode())  # send data to the client

    conn.close()  # close the connection

def create_safe_channel(private_key_server,public_key_server):


    return public_key_client


if __name__ == '__main__':
    SPR_KEY , curve = enc.get_private_key()
    SPUB_KEY = enc.get_public_key(SPR_KEY,curve)
    msg = b"this is test."
    crypt = enc.encrypt_ECC(msg,SPUB_KEY,curve)
    new_msg = enc.decrypt_ECC(crypt,SPR_KEY)
    print(new_msg)
    # server_program()