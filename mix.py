# Maria Dach, 208539080, Shira Negbi, 313236911

import socket
import sys
import random
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# a server that listens to messages, shuffles their order, decrypts them and forwards every 60 seconds
class MixServer:
    def __init__(self, file_number):
        self.file_number = file_number
        self.file = None
        self.key = None
        self.fernet = None
        self.received_messages = []
        self.ip = None
        self.port = -1
        self.buffer_size = 0
        self.messages_lock = threading.Lock()
        self.load_key()
        self.init_tcp_params()

    # open and read the proper skY.pem file where Y is an int argument
    def read_file(self):
        file_name = "sk" + str(self.file_number) + ".pem"
        file = open(file_name, "r")
        self.file = file
        return file.read()

    # close the skY.pem file
    def close_file(self):
        self.file.close()

    # load the cryptographic key out of the file
    def load_key(self):
        key_text = self.read_file()
        self.key = load_pem_private_key(key_text.encode(), None)
        self.close_file()

    # initialize the tcp parameters by the ips file
    def init_tcp_params(self):
        file = open("ips.txt", "r")
        lines = file.readlines()

        # pick the proper line by the number of the server
        line = lines[int(self.file_number) - 1]
        num_servers = len(lines)
        self.buffer_size = max(8192, 1024 * pow(2, num_servers))
        ip, port = line.split(" ")
        self.ip = ip
        self.port = int(port)

    # listen to tcp messages by the given parameters
    def receive_messages(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", self.port))
        s.listen()

        while True:

            # add each received message to the list
            conn, addr = s.accept()
            msg = conn.recv(self.buffer_size)
            conn.close()
            lock_aquired = self.messages_lock.acquire(False)
            while not lock_aquired:
                lock_aquired = self.messages_lock.acquire(False)
            self.received_messages.append(msg)
            self.messages_lock.release()

    # forward a message to its destination
    def forward_message(self, dst_ip, dst_port, msg):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((dst_ip, dst_port))
        s.send(msg)
        s.close()

    # decrypt a message by the cryptographic key
    def decrypt_message(self, msg):
        text = self.key.decrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return text

    # decrypt a message and separate the ip and the port from the rest
    def decrypt_message_ip_port(self, msg):
        decrypted_msg = self.decrypt_message(msg)
        dst_ip = decrypted_msg[:4]
        dst_ip = ".".join([str(x) for x in dst_ip])
        dst_port = decrypted_msg[4:6]
        dst_port = int.from_bytes(dst_port,'big')
        text = decrypted_msg[6:]
        return dst_ip, dst_port, text

    # shuffle the messages received so far, decrypt and forward them
    def forward_all_messages(self):
        lock_aquired = self.messages_lock.acquire(True)
        while not lock_aquired:
            lock_aquired = self.messages_lock.acquire(True)
        messages = self.received_messages[:]
        self.received_messages = []
        self.messages_lock.release()
        random.shuffle(messages)
        for msg in messages:

            # decrypt each message and send the result to the ip and port appended to its beginning
            dst_ip, dst_port, m = self.decrypt_message_ip_port(msg)
            self.forward_message(dst_ip, dst_port, m)

def main():

    # start a mix server with its number
    mix_server = MixServer(sys.argv[1])

    # receive and send messages simultaneously
    threading.Thread(target=mix_server.receive_messages).start()
    while True:

        # wait 60 seconds before sending the next group of messages
        t = threading.Timer(60, mix_server.forward_all_messages)
        t.start()
        t.join()


main()
