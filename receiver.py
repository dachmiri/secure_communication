import socket
import sys

from datetime import datetime


class Receiver:
    def __init__(self, password, salt, port):
        self.password = password
        self.salt = salt
        self.port = port
        self.buffer_size = 8192  # TODO: check instructions

    def receive_messages(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", self.port))
        s.listen()

        while True:
            conn, addr = s.accept()
            message = conn.recv(self.buffer_size)
            time = datetime.now().strftime("%H:%M:%S")
            # TODO: decrypt message
            print(str(message) + " " + time)
            conn.close()

def main():
    receiver = Receiver(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    receiver.receive_messages()


main()