import sys
import base64
import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization




class Info:
    def __init__(self, message, path, round, password, salt, dest_ip, dest_port, to_send, mix_ip, mix_port):
        self.message = message
        self.path = path
        self.round = round
        self.password = password
        self.salt = salt
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.to_send = to_send
        self.mix_ip = mix_ip
        self.mix_port = mix_port

    def __init__(self):
        self.message = ""
        self.path = ""
        self.round = ""
        self.password = ""
        self.salt = ""
        self.dest_ip = ""
        self.dest_port = ""
        self.to_send = ""
        self.mix_ip = ""
        self.mix_port = ""

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

    def get_mix_port(self):
        return self.mix_port

    def get_mix_ip(self):
        return self.mix_ip

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

    def set_mix_port(self, mix_port):
        self.mix_port = mix_port

    def set_mix_ip(self, mix_ip):
            self.mix_ip = mix_ip


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
        salt=salt.encode(),
        iterations=100000, )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    return key


def encrypt_server_info(path, msg):
    # create a list of all server numbers in the path
    servers = path.split(",")
    # last server in path should be encrypted first
    servers.reverse()
    # get ips and ports for all servers
    ips_file = open("ips.txt", 'r')
    ips = ips_file.readlines()

    ip = ""
    port = ""

    prev_server = ""
    first_server = True

    for server in servers:
        # get public key for this server
        pk_file_name = "pk" + server + ".pem"
        pk_file = open(pk_file_name, 'r')
        key = pk_file.read()
        # get IP and port for prev server
        if not first_server:
            prev_server_num = int(prev_server)
            servers_ip = ips[prev_server_num - 1]
            servers_ip = servers_ip.split(" ")
            ip = servers_ip[0]
            port = servers_ip[1].strip('\n')


        # encrypt the message with the ip and port and set it as the message for the next server
        encrypted_msg = encrypt_with_rsa_key(key, msg, ip, port, first_server)
        msg = encrypted_msg

        first_server = False
        prev_server = server

    server_num = int(servers[-1])
    servers_ip = ips[server_num - 1]
    servers_ip = servers_ip.split(" ")
    ip = servers_ip[0]
    port = servers_ip[1].strip('\n')

    return msg, ip, port




def encrypt_alices_msg(info):
    key = create_key(info.get_password(), info.get_salt())
    full_message = encrypt(info.get_message(), info.get_dest_ip(), info.get_dest_port(), key)

    msg, ip, port = encrypt_server_info(info.get_path(), full_message)

    info.set_to_send(msg)
    info.set_mix_ip(ip)
    info.set_mix_port(port)



def encrypt_with_rsa_key(key, msg, ip, port, first_server):

    full_message = msg

    if not first_server:
        port = int(port).to_bytes(2, 'big')
        ip = bytes(map(int, ip.split('.')))
        full_message = ip + port + msg

    public_key = serialization.load_pem_public_key(key.encode())

    ciphertext = public_key.encrypt(
        full_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def encrypt(message, ip, port, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    port = int(port).to_bytes(2, 'big')
    ip = bytes(map(int,ip.split('.')))
    full_message = ip + port + encrypted_message

    return full_message

def send_msgs(infos, round):
    print(round)
    for info in infos:
        if info.get_round() == round:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.connect((info.get_mix_ip(), int(info.get_mix_port())))

            s.send(info.get_to_send())

            s.close()

    round += 1


def get_max_round(infos):
    max_round = 0
    for info in infos:
        # Convert round to int for this function and next cases
        info.set_round(int(info.get_round()))
        if info.get_round() > max_round:
            max_round = info.get_round()
    return max_round

def main():
    infos = get_parameters()

    for info in infos:
        encrypt_alices_msg(info)

    max_round = get_max_round(infos)
    round = 0

    # Send first round without wait
    t = threading.Timer(10, send_msgs, [infos, round])
    t.start()
    t.join()

    # Wait 60 seconds and send next round
    for round in range(1, max_round + 1):
        t = threading.Timer(60, send_msgs, [infos, round])
        t.start()
        t.join()


if __name__ == '__main__':
    main()
