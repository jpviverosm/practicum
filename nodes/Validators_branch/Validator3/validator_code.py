from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from signal import signal, SIGINT
import sys
import os
import os.path
import json
import time
from OpenSSL import crypto
import random
from filehash import FileHash
import glob

# Global Variables

'''
HOST = '127.0.0.1'
PORT = 33336
BUFFERSIZE = 1024
ADDR = (HOST, PORT)
ACTION = ''
NAME = 'Validator3'
BCNETWORKNUM = 0
BCNETWORKNODES = []
VALIDATORS_LIST = []
EXIT = False
VALIDATORS_DICT = {}
'''


#####################################################################################################################################
### Communication handling functions
#####################################################################################################################################

def receive_msg():
    global VALIDATORS_LIST
    while True:
    #while not EXIT:
        if EXIT:
            break
        try:
            msg = client_socket.recv(BUFFERSIZE)
            msg_json = json.loads(msg)


            if msg_json['net_action'] == 'confirm_name':
                print('Name: {}'.format(msg_json['name']))

            elif msg_json['net_action'] == 'new_node':
                if msg_json['client_name'] != NAME:
                    print('{} has joined the network'.format(msg_json['client_name']))

                    if msg_json['validator'] == True:
                        if VALIDATORS_LIST:
                            #print("Control point printing validators list: {}".format(VALIDATORS_LIST))
                            if msg_json['client_name'] not in VALIDATORS_LIST:
                                time.sleep(VAL_NUM)
                                print("adding {} to the validators list".format(msg_json['client_name']))
                                VALIDATORS_LIST.append(msg_json['client_name'])
                                req_cert(msg_json['client_name'])

                                


            elif msg_json['net_action'] == 'confirm_list':
                BCNETWORKNUM = msg_json['real_clients_num']
                BCNETWORKNODES = msg_json['real_clients_name']
                VALIDATORS_LIST = msg_json['validators']                

                #print(BCNETWORKNUM)
                print("Blockchain network nodes: {}".format(BCNETWORKNODES))
                print("Validators list: {}". format(VALIDATORS_LIST))
                

            elif msg_json['net_action'] == 'confirm_exit':
                print('{} has left the network'.format(msg_json['client_leaving']))

            elif msg_json['net_action'] == 'unicast()':
                print(msg_json)
                if msg_json['file'] == True:
                    recvfile(msg_json['filename'])

                if msg_json['bcaction'] != '':    
                    blockchain_action(msg_json)

            elif msg_json['net_action'] == 'broadcast()':
                print(msg_json)
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
            print('tranmission complete')
        else:
            #file_bytes += bytes_read
            print('receiving data...')
    file_bytes = file_bytes[:-2]
    print(file_bytes)
    fd.write(file_bytes)
        #else:
        #    # write to the file the bytes we just received
        #    print('receiving data...')
        #    fd.write(bytes_read)
        #    bytes_read = client.recv(BUFFERSIZE)
    print('closing file')
    fd.close()
    

def sendfile(filename):
    fd = open(filename, "rb")
    while True:
        # read the bytes from the file
        bytes_read = fd.read()
        print(bytes_read)
        if not bytes_read:
            # file transmitting is done
            print('file completely read')
            break
        while bytes_read:
            # we use sendall to assure transimission in 
            # busy networks
            print('sending data...')
            client_socket.sendall(bytes_read)
            bytes_read = fd.read()
    print('closing file')
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
    if fileflag:
        time.sleep(0.5)
        sendfile(filename)

def network():
    payload = {
        'net_action': 'online()',
    }

    send_msg(payload)

def name(name):
    payload = {
        'net_action': 'name()',
        'bcaction': 'add_validator',
        'validator': True,
        'file': False,
        'name': name
    }

    send_msg(payload)

#####################################################################################################################################
### Certificate handling functions
#####################################################################################################################################

# Taken from https://github.com/iquzart/python-digital-certificate/blob/master/digital-cert.py
def create_own_cert():
    own_key = crypto.PKey()
    own_key.generate_key(crypto.TYPE_RSA, 4096)

    own_cert = crypto.X509()
    own_cert.set_version(2)
    own_cert.set_serial_number(random.randint(50000000, 100000000))

    ca_subj = own_cert.get_subject()
    ca_subj.countryName = 'US'
    ca_subj.stateOrProvinceName = 'NC'
    ca_subj.localityName = 'Charlotte'
    ca_subj.organizationName = 'Practicum'
    ca_subj.organizationalUnitName = 'Validators'
    ca_subj.commonName = NAME
    ca_subj.emailAddress = NAME + '@validators.com'
    
    own_cert.set_issuer(ca_subj)
    own_cert.set_pubkey(own_key)

    own_cert.gmtime_adj_notBefore(0)
    own_cert.gmtime_adj_notAfter(10*365*24*60*60)

    own_cert.sign(own_key, 'sha256')

    # Save certificate
    f_cert = open(NAME+'.crt', "wt")
    f_cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, own_cert).decode("utf-8"))
    f_cert.close()
    print("Validator Certificate generated successfully")

    # Save private key
    f_key =  open(NAME+'.key', "wt")
    f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, own_key).decode("utf-8"))
    f_key.close()
    print("Validator Key generated successfully")

    # add itself to the vaidators dictionary
    #pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, own_key).decode("utf-8")
    pub_key = own_cert.get_pubkey()
    VALIDATORS_DICT[NAME] = pub_key
    VALIDATORS_LIST.append(NAME)

def issue_cert(csr_file, requestor_name):
    # load certificate
    issuer_cert_file = NAME + ".crt"
    issuer_key_file = NAME + ".key"
    f1 = open(issuer_cert_file, "r")
    issuer_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f1.read())
    f1.close()
    # load private key for certificate signing
    f2 = open(issuer_key_file, "r")
    issuer_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f2.read())
    f2.close()

    #create certificate
    cert = crypto.X509()
    f_csr = open(csr_file, 'r')
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, f_csr.read())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_serial_number(1000)
    cert.set_issuer(issuer_cert.get_subject())
    f_csr.close()

    # sign certificate
    cert.sign(issuer_key, 'sha256')

    # store certificate locally to send later
    f3 = open(requestor_name + ".crt", "wt")
    f3.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

    print('Certificate created successfully')



def extract_public_key(cert):
    print('Extracting public key for {}'.format(cert))
    f = open(cert, "r")
    pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
    f.close()
    return pub_key

def req_cert(name):
    unicast(name, 'Requesting Certificate', '', 'req_cert')


#####################################################################################################################################
### Blockchain handling functions
#####################################################################################################################################
    
def blockchain_action(msg_json):
    if msg_json['bcaction'] == "issue":
        csr_file = msg_json['filename']
        requestor_name = msg_json['name']

        # Get the last block in the blockchain
        folder_path = './blockchain/*'
        file_type = r'\*txt'
        files = glob.glob(folder_path)
        latest_block = max(files, key=os.path.getctime)

        # Get the hash of the last block
        sha256hasher = FileHash('sha256')
        block_hash = sha256hasher.hash_file(latest_block)
        block_hash_int = int(block_hash, 16)

        print("last block hash: {}".format(block_hash))
        print("hash % {}: {}".format(len(VALIDATORS_LIST), block_hash_int % len(VALIDATORS_LIST)))

        selected_val = (block_hash_int % len(VALIDATORS_LIST)) + 1
        print("Validator{} has been selected to issue certificate".format(selected_val))

        # Select validator to issue certificate
        #if (block_hash_int % VAL_NUM) == (VAL_NUM - 1):
        if selected_val == VAL_NUM:
            issue_cert(csr_file, requestor_name)

    #elif msg_json['bcaction'] == "add_validator":
    #    add_validator(msg_json)

    elif msg_json['bcaction'] == "req_cert":
        unicast(msg_json['name'], 'Sending Certificate', NAME + '.crt', 'add_key')

    elif msg_json['bcaction'] == "add_key":
        add_validator_key(msg_json['name'])
    

def add_validator_key(validator_name):
    print("adding keys to the validators dictionary")
    f = open(validator_name + '.crt', "r")
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    pub_key = cert.get_pubkey()
    f.close()
    VALIDATORS_DICT[validator_name] = pub_key
    print("Validator node added successfully")
    print("Validators:")
    print(VALIDATORS_DICT)

    

    




def menu():
    selected = 0
    #exit = False

    while not EXIT:
        time.sleep(0.3)
        print("\n1. Unicast.\n2. Broadcast.\n3. Network.\n4. Exit")
        selected = input("Selected option: ")
        if int(selected) == 1:
            #print("Available nodes: ")
            #network()
            dest = input("\nType destination node: ")
            file = input("\nSend file? Y/N: ")
            if file == "Y":
                #unicast(dest, 'test', 'test.pem')
                unicast(dest, 'test', 'test_val1.txt')
            else:
                unicast(dest, 'test')
        if int(selected) == 2:
            print("\nBroadcasting")
            file = input("\nSend file? Y/N: ")
            if file == "Y":
                broadcast('test', 'test_val1.txt')
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
    #VAL_NUM = 1
    VAL_NUM = int(sys.argv[1])
    NAME = 'Validator' + str(VAL_NUM)
    BCNETWORKNUM = 0
    BCNETWORKNODES = []
    VALIDATORS_LIST = []
    EXIT = False
    VALIDATORS_DICT = {}
    

    create_own_cert()
    
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(ADDR)
    receive_thread = Thread(target=receive_msg)
    receive_thread.start()

    # set name 
    name(NAME)
    #print("validators list: {}".format(VALIDATORS_LIST))

    time.sleep(1)
    network()
    time.sleep(2)

    print("test line 419, validators list: {}".format(VALIDATORS_LIST))

    for val in VALIDATORS_LIST:
        print("iterating validators list: {}".format(val))
        if val != NAME:
            print("Adding {} to the dictionary".format(val))
            req_cert(val)
            time.sleep(1)
            #add_validator_key(val)
            #time.sleep(1)

    #print("Validator:")
    #print(VALIDATORS_DICT)

    #menu()
