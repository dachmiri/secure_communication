# import base64
import socket
import sys

# from cryptography.fernet import Fernet
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
        self.load_key()
        # self.init_fernet()

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
        # self.key = base64.b64encode(key_text.encode())
        self.close_file()

    # def init_fernet(self):
    #     self.fernet = Fernet(self.key)

    # forward a message to its destination
    def forward_massage(self, dst_ip, dst_port, msg):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((dst_ip, dst_port))
        s.send(msg)
        s.close()

    def decrypt_message(self, msg):
        # text = self.fernet.decrypt(msg)  # maybe msg.encode()
        text = self.key.decrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return text

    def decrypt_message_by_parts(self, msg):
        dst_ip = msg[:4]
        dst_ip = self.decrypt_message(dst_ip)
        dst_port = msg[4:6]
        dst_port = self.decrypt_message(dst_port)
        text = msg[6:]
        text = self.decrypt_message(text)
        return dst_ip, dst_port, text
        # TODO: validate with a real message from alice

    def forward_all_messages(self):
        pass

def main():
    mix_server = MixServer(sys.argv[1])
    # s = "1234567890"
    # print(s[:4])
    # print(s[4:6])
    # print(s[6:])

    # TODO: implemet decrypting and forwarding a single message.
    # TODO: send all current messages (copy from the queue and start a new queue) by a timer (see saved example)
    # TODO: receive messages in parallel with the sending
    # TODO: get argument, wait for the defined time (by loop?), receive messages and forward all. change self.file_number and self.file if needed.


main()
