import socket
import sys
import random
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


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
        self.load_key()
        self.init_tcp_params()

    def read_file(self):
        file_name = "sk" + str(self.file_number) + ".pem"
        file = open(file_name, "r")
        self.file = file
        return file.read()

    def close_file(self):
        self.file.close()

    def load_key(self):
        key_text = self.read_file()
        self.key = load_pem_private_key(key_text.encode(), None)
        self.close_file()

    def init_tcp_params(self):
        file = open("ips.txt", "r")
        lines = file.readlines()
        line = lines[int(self.file_number) - 1]
        num_servers = len(lines)
        self.buffer_size = max(8192, 1024 * pow(2, num_servers))
        ip, port = line.split(" ")
        self.ip = ip
        self.port = int(port)

    def receive_messages(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", self.port))
        s.listen()

        while True:
            conn, addr = s.accept()
            self.received_messages.append(conn.recv(self.buffer_size))

            #############################################################
            num_msg = len(self.received_messages)
            print("Message number " + str(num_msg) + ":\n")
            print(self.received_messages[num_msg - 1])
            print()
            #############################################################

            conn.close()

    # forward a message to its destination
    def forward_message(self, dst_ip, dst_port, msg):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((dst_ip, dst_port))
        s.send(msg)
        s.close()

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

    def decrypt_message_ip_port(self, msg):
        decrypted_msg = self.decrypt_message(msg)
        dst_ip = decrypted_msg[:4]
        dst_ip = ".".join([str(x) for x in dst_ip])
        dst_port = decrypted_msg[4:6]
        dst_port = int.from_bytes(dst_port,'big')
        text = decrypted_msg[6:]
        return dst_ip, dst_port, text

    def forward_all_messages(self):
        # TODO: lock self.received_messages
        messages = self.received_messages[:]
        num_msg = len(messages)
        self.received_messages = self.received_messages[num_msg:]
        random.shuffle(messages)
        for msg in messages:
            dst_ip, dst_port, m = self.decrypt_message_ip_port(msg)

            ###########################################################
            print("ip: " + dst_ip)
            print("port: " + str(dst_port))
            print("decrypted message: ")
            print(m)
            print()
            ###########################################################

            self.forward_message(dst_ip, dst_port, m)
        # TODO: unlock self.received_messages

def main():
    mix_server = MixServer(sys.argv[1])
    threading.Thread(target=mix_server.receive_messages).start()
    while True:
        t = threading.Timer(60, mix_server.forward_all_messages)
        t.start()
        t.join()

    # TODO: delete debug prints in all files
    # TODO: add submission details in all three files
    # TODO: document and submit


main()
