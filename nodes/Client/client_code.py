from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from signal import signal, SIGINT
import sys
import os
import json
import time
from filehash import FileHash
from merkly.mtree import MerkleTree
from OpenSSL import crypto
import ast
from datetime import date
from datetime import datetime

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
  
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
  
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))
  
def prLightPurple(skk): print("\033[94m {}\033[00m" .format(skk))
  
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk))
  
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
  
def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))
 
def prBlack(skk): print("\033[98m {}\033[00m" .format(skk))

def receive_msg():
    global BCNETWORKNODES
    while True:
    #while not EXIT:
        if EXIT:
            break
        try:
            msg = client_socket.recv(BUFFERSIZE)
            msg_json = json.loads(msg)

            if msg_json['net_action'] == 'confirm_name':
                prCyan('Name: {}'.format(msg_json['name']))

            elif msg_json['net_action'] == 'new_node':
                prCyan('{} has joined the network'.format(msg_json['client_name']))


            elif msg_json['net_action'] == 'confirm_list':
                BCNETWORKNUM = msg_json['real_clients_num']
                BCNETWORKNODES = msg_json['real_clients_name']

                #print(BCNETWORKNUM)
                prCyan(BCNETWORKNODES)

            elif msg_json['net_action'] == 'confirm_exit':
                prCyan('{} has left the network'.format(msg_json['client_leaving']))

            elif msg_json['net_action'] == 'unicast()':
                print("\n")
                prPurple(msg_json)
                print("\n")
                if msg_json['file'] == True:
                    recvfile(msg_json['filename'])
                if msg_json['bcaction'] != '':    
                    blockchain_action(msg_json)

            elif msg_json['net_action'] == 'broadcast()':
                print("\n")
                prPurple(msg_json)
                print("\n")
                if msg_json['file'] == True:
                    recvfile(msg_json['filename'])
                if msg_json['bcaction'] != '':    
                    blockchain_action(msg_json)

        except OSError as error:
            return error
        
def recvfile(filename):
    filename = os.path.basename(filename)
    fd = open(filename, "wb")

    # read 1024 bytes from the socket (receive)
    #bytes_read = client.recv(BUFFERSIZE)
    #print(bytes_read)
    done = False
    file_bytes = b""
    while not done:
        #print('control test')
        bytes_read = client_socket.recv(BUFFERSIZE)
        #print('bytes read: {}'.format(bytes_read))
        #print('terminate signal: {}'.format(bytes_read[-2:]))
        #print('file bytes: {}'.format(file_bytes))
        file_bytes += bytes_read
        if bytes_read[-2:] == b"<>":
            done = True
            prYellow('tranmission complete')
        else:
            #file_bytes += bytes_read
            prYellow('receiving data...')
    file_bytes = file_bytes[:-2]
    print("\n")
    print(file_bytes)
    print("\n")
    fd.write(file_bytes)
        #else:
        #    # write to the file the bytes we just received
        #    print('receiving data...')
        #    fd.write(bytes_read)
        #    bytes_read = client.recv(BUFFERSIZE)
    prYellow('closing file')
    fd.close()


def sendfile(filename):
    fd = open(filename, "rb")
    while True:
        # read the bytes from the file
        bytes_read = fd.read()
        print("\n")
        print(bytes_read)
        print("\n")
        if not bytes_read:
            # file transmitting is done
            prYellow('file completely read')
            break
        while bytes_read:
            # we use sendall to assure transimission in 
            # busy networks
            prYellow('sending data...')
            client_socket.sendall(bytes_read)
            bytes_read = fd.read()
    prYellow('closing file')
    fd.close()
    client_socket.send(bytes("<>", "utf-8"))


def send_msg(payload):
    try:
        msg = json.dumps(payload)
        client_socket.send(msg.encode('utf8'))
    except EOFError:
        clean_exit()

def clean_exit():
    payload = {
        'net_action': 'exit()',
        'name': NAME
    }
    send_msg(payload)
    client_socket.close()
    EXIT = True
    sys.exit(0)

def handler(signal_recv, frame):
    clean_exit()

def unicast(destination, message = '', filename = '', bcaction = ''):
    fileflag = False
    if filename != '':
        fileflag = True
    payload = {
        'name': NAME,
        'net_action': 'unicast()',
        'bcaction': bcaction,
        'file': fileflag,
        'filename': filename,
        'destination': destination,
        'message': message
    }

    send_msg(payload)
    if fileflag:
        time.sleep(0.5)
        sendfile(filename)

def broadcast(message = '', filename = '', bcaction = ''):
    fileflag = False
    if filename != '':
        fileflag = True
    payload = {
        'name': NAME,
        'net_action': 'broadcast()',
        'bcaction': bcaction,
        'file': fileflag,
        'filename': filename,
        'destination': '',
        'message': message
    }

    send_msg(payload)

def network():
    payload = {
        'net_action': 'online()',
    }

    send_msg(payload)

def name(name):
    payload = {
        'net_action': 'name()',
        'bcaction': '',
        'validator': False,
        'file': False,
        'name': name
    }

    send_msg(payload)

#####################################################################################################################################
### Blockchain handling functions
#####################################################################################################################################

def blockchain_action(msg_json):     
    if msg_json["bcaction"] == "recv_block":
        header = msg_json['message']
        json_object = json.dumps(header, indent=4)
        f = open("./blockchain/last_block.json", "w")
        f.write(json_object)
        f.close()
        prGreen("last block added successfully")

    elif msg_json['bcaction'] == "recv_proof":
        cert_hash_list = msg_json["message"][0]
        cert_hash_list = ast.literal_eval(cert_hash_list)
        prYellow("Cert hash list: {}".format(cert_hash_list))
        prYellow("cert hash list type: {}".format(type(cert_hash_list)))
        proof_str = msg_json["message"][1]
        server = msg_json["message"][2]
        

        f = open("./blockchain/last_block.json", "r")
        data = f.read()
        f.close()
        data_json = json.loads(data)
        read_root = data_json["Certificates_Merkle_root"]
        certs_mtree = MerkleTree(cert_hash_list)
        calc_root = certs_mtree.root.hex()
        prYellow("Checkpoint, Calc root: {}, read root: {}".format(calc_root, read_root))

        if read_root == calc_root:
            prYellow("Checking")
            sha256hasher = FileHash('sha256')
            cert_hash = sha256hasher.hash_file(server + ".crt")
            prYellow("Certificate hash: {}".format(cert_hash))
            try:
                calc_proof = certs_mtree.proof(cert_hash)
                if certs_mtree.verify(calc_proof, cert_hash):
                    prGreen("Verification passed")
                    if str(calc_proof) == proof_str:
                        prGreen("Certificate membership in the blockchain validated successfully")
                    else:
                        prRed("received proof does not match with calculated proof")
                else:
                    prRed("Merkle proof verification for certificate failed")
            except:
                prRed("Certificate invalid. No membership in the blockchain")
        else:
            prRed("Merkle roots don't match")



    elif msg_json['bcaction'] == "add_key":

        cert_file = msg_json['filename']
        server = msg_json['name']

        f_cert = open(cert_file, 'r')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f_cert.read())
        f_cert.close()

        date_bytes = cert.get_notAfter()
        cert_date_string = date_bytes.decode('utf-8')
        cert_date = datetime.strptime(cert_date_string, '%Y%m%d%H%M%S%z').date()

        today = date.today()
        prYellow("Certificate expiration date: {}".format(cert_date))
        prYellow("Today's date: {}".format(today))

        if today >= cert_date:
            prRed("Certificate Expired")

        else:
            prGreen("Certificate not expired, requesting Merkle proof...")

            issuer = cert.get_issuer().commonName
            prYellow("Issuer: {}".format(issuer))

            sha256hasher = FileHash('sha256')
            cert_hash = sha256hasher.hash_file(cert_file)
            prYellow("cert hash: {}".format(cert_hash))
            msg = []
            msg.append(cert_hash)
            msg.append(server)
            unicast(issuer, msg, "", "req_Merkle")

def menu():
    selected = 0
    #exit = False

    while not EXIT:
        time.sleep(0.3)
        print("\n1. Connect to server.\n2. Broadcast.\n3. Network.\n4. Exit")
        selected = input("Selected option: \n")
        if int(selected) == 1:
            network()
            time.sleep(0.2)
            server = input("Provide the name of server: ")
            #print(BCNETWORKNODES)
            if server in BCNETWORKNODES:
                
                unicast(server, "Requesting Certificate", "", "req_cert")
            else:
                prRed("{} is not in the blockchain network...". format(server))
            
        if int(selected) == 2:
            prYellow("\nBroadcasting")
            file = input("\nSend file? Y/N: ")
            if file == "Y":
                broadcast('test', 'test_client1.txt')
            else:
                broadcast('test')
        if int(selected) == 3:
            network()
        if int(selected) == 4:
            clean_exit()


        #else:
        #    print("\nSelect a valid option:")
            


if __name__ == '__main__':
    signal(SIGINT, handler)
    HOST = '127.0.0.1'
    PORT = 33336
    BUFFERSIZE = 1024
    ADDR = (HOST, PORT)
    ACTION = ''
    VAL_NUM = int(sys.argv[1])
    NAME = 'Client' + str(VAL_NUM)
    #NAME = 'Client1'
    BCNETWORKNUM = 0
    BCNETWORKNODES = []
    EXIT = False
    PAYLOAD = {
        'action': '',
        'file': False,
        'name': NAME
    }

    sha256hasher = FileHash('sha256')
    code_hash = sha256hasher.hash_file(sys.argv[0])

    f = open("./blockchain/block1.json", "r")
    data = f.read()
    f.close()
    data_json = json.loads(data)
    block_code_hash = data_json["Client_Code_Hash"]

    if code_hash == block_code_hash:
        prGreen("Smart Contract validated successfully")
        prGreen("Client code hash: {}".format(code_hash))
        prGreen("Smart contract hash: {}".format(block_code_hash))

    else:
        prRed("Smart Contract Validation failed, hashes don't match")
        prRed("Client code hash: {}".format(code_hash))
        prRed("Smart contract hash: {}".format(block_code_hash))
        print("\n")
        prRed("Aborting...")
        clean_exit()

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(ADDR)
    receive_thread = Thread(target=receive_msg)
    receive_thread.start()

    # set name 
    #PAYLOAD['net_action'] = 'name()'
    #send_msg(PAYLOAD)
    name(NAME)

    time.sleep(0.5)

    menu()
