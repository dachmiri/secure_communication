# Maria Dach, 208539080, Shira Negbi, 313236911

import socket
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from datetime import datetime


class Receiver:
    def __init__(self, password, salt, port):
        self.password = password
        self.salt = salt
        self.port = port
        self.buffer_size = 8192
        self.key = None
        self.fernet = None
        self.init_key()
        self.init_fernet()

    def init_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            iterations=100000, )
        self.key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))

    def init_fernet(self):
        self.fernet = Fernet(self.key)

    def decrypt_message(self, msg):
        return self.fernet.decrypt(msg)

    def receive_messages(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", self.port))
        s.listen()

        while True:
            conn, addr = s.accept()
            message = conn.recv(self.buffer_size)
            time = datetime.now().strftime("%H:%M:%S")
            decrypted = self.decrypt_message(message)
            print(decrypted.decode() + " " + time)
            conn.close()

def main():
    receiver = Receiver(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    receiver.receive_messages()


main()