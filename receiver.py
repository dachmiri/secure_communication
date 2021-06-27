# Maria Dach, 208539080, Shira Negbi, 313236911

import socket
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

# a client that receives encrypted messages, decrypts them and prints them
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

    # initialize the symmetric cryptographic key
    def init_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            iterations=100000, )
        self.key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))

    # initialize fernet by the key
    def init_fernet(self):
        self.fernet = Fernet(self.key)

    # decrypt a message using fernet
    def decrypt_message(self, msg):
        return self.fernet.decrypt(msg)

    # listen to tcp messages based on the given parameters
    def receive_messages(self):

        # init socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", self.port))
        s.listen()

        while True:

            # receive a message over a connection
            conn, addr = s.accept()
            message = conn.recv(self.buffer_size)

            # print decrypted message and the time it was received
            time = datetime.now().strftime("%H:%M:%S")
            decrypted = self.decrypt_message(message)
            print(decrypted.decode() + " " + time)
            conn.close()

def main():

    # init the receiver with the password (str), salt (str) and tcp port number
    receiver = Receiver(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    receiver.receive_messages()


main()