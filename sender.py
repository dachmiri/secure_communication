import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Info:
    def __init__(self, message, path, round, password, salt, dest_ip, dest_port, to_send):
        self.message = message
        self.path = path
        self.round = round
        self.password = password
        self.salt = salt
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.to_send = to_send

    def __init__(self):
        self.message = ""
        self.path = ""
        self.round = ""
        self.password = ""
        self.salt = ""
        self.dest_ip = ""
        self.dest_port = ""
        self.to_send = ""

    def get_message(self):
        return self.message

    def get_path(self):
        return self.path

    def get_round(self):
        return self.round

    def get_password(self):
        return self.password

    def get_salt(self):
        return self.salt

    def get_dest_ip(self):
        return self.dest_ip

    def get_dest_port(self):
        return self.dest_port

    def get_to_send(self):
        return self.to_send

    def set_message(self, message):
        self.message = message

    def set_path(self, path):
        self.path = path

    def set_round(self, round):
        self.round = round

    def set_password(self, password):
        self.password = password

    def set_salt(self, salt):
        self.salt = salt

    def set_dest_ip(self, dest_ip):
        self.dest_ip = dest_ip

    def set_dest_port(self, dest_port):
        self.dest_port = dest_port

    def set_to_send(self, to_send):
        self.to_send = to_send


# This function in charge of retrieving the parameters from messagesX.txt file
def get_parameters():
    X = sys.argv[1]
    file_name = "messages" + X + ".txt"
    file = open(file_name, 'r')
    # This array will hold 'Info' instances
    # each Info hold the information for one message
    infos = []

    line = file.readline()
    while (line):
        words = line.split(" ")
        info = Info()

        # Set Info
        info.set_message(words[0])
        info.set_path(words[1])
        info.set_round(words[2])
        info.set_password(words[3])
        info.set_salt(words[4])
        info.set_dest_ip(words[5])
        info.set_dest_port(words[6])

        infos.append(info)

        line = file.readline()

    return infos


def create_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key


def encrypt_server_info(path, msg):
    # create a list of all server numbers in the path
    servers = path.split(",")
    # last server in path should be encrypted first
    servers.revers()
    # get ips and ports for all servers
    ips_file = open("ips.txt", 'r')
    ips = ips_file.readlines()

    for server in servers:
        # get public key for this server
        pk_file_name = "pk" + server + ".pem"
        pk_file = open(pk_file_name, 'r')
        key = pk_file.readline()
        # get IP and port for this server
        server_num = int(server)
        servers_ip = ips[server_num]
        servers_ip = servers_ip.split(" ")
        ip = servers_ip[0]
        port = servers_ip[1]

        # encrypt the message with the ip and port and set it as the message for the next server
        encrypted_msg = encrypt(msg, ip, port, key)
        msg = encrypted_msg

    return msg


def encrypt_alices_msg(info):
    key = create_key(info.get_password(), info.get_salt())
    full_message = encrypt(info.get_message(), info.get_dest_ip(), info.get_dest_port(), key)

    encrypt_server_info(info.get_path(), full_message)





def encrypt(message, ip, port, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message())
    full_message = ip | port | encrypted_message

    return full_message


def main():
    infos = get_parameters()

    for info in infos:
        encrypt_alices_msg(info)


if __name__ == '__main__':
    main()
