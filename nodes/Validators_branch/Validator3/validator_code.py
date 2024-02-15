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
from merkly.mtree import MerkleTree
import hashlib
import warnings
import math


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
    
    own_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=own_cert),
    ])

    own_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=own_cert),
    ])

    own_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
    ])
    

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

def issue_cert(csr_file, requestor_name, latest_block_hash):
    global CERTS_HASH_LIST
    global ISSUED_DOMAINS

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
    f3.close()

    # add cert hash to the hash list
    sha256hasher = FileHash('sha256')
    pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()))
    domain = str(cert.get_subject().commonName)

    update_dicts(requestor_name, latest_block_hash, pub_key_hash, domain)
    '''
    # need at least 2 elements in list to build the merkle tree, if list is empty, add the latest block hash as the first hash in list
    if len(CERTS_HASH_LIST) < 1:
        CERTS_HASH_LIST.append(latest_block_hash)

    CERTS_HASH_LIST.append(sha256hasher.hash_file(requestor_name + ".crt"))

    # add domain to the issued domains list
    # need at least 2 elements in list to build the merkle tree, if list is empty, add "Genesis" as the first domain in list
    if len(ISSUED_DOMAINS.keys()) < 1:
        ISSUED_DOMAINS.update({"Genesis": hashlib.sha256("Genesis".encode()).hexdigest()})

    #ISSUED_DOMAINS.append(str(cert.get_subject().commonName))
    #print(ISSUED_DOMAINS)
        
    pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()))
        
    #ISSUED_DOMAINS.update({str(cert.get_subject().commonName): csr.get_pubkey()})
    ISSUED_DOMAINS.update({str(cert.get_subject().commonName): pub_key_hash.hexdigest()})
    print(ISSUED_DOMAINS)
    '''

    print('Certificate created successfully')


def update_dicts(requestor_name, latest_block_hash, pub_key_hash, domain):
    # add cert hash to the hash list
    sha256hasher = FileHash('sha256')
    # need at least 2 elements in list to build the merkle tree, if list is empty, add the latest block hash as the first hash in list
    if len(CERTS_HASH_LIST) < 1:
        CERTS_HASH_LIST.append(latest_block_hash)

    CERTS_HASH_LIST.append(sha256hasher.hash_file(requestor_name + ".crt"))

    # add domain to the issued domains list
    # need at least 2 elements in list to build the merkle tree, if list is empty, add "Genesis" as the first domain in list
    if len(ISSUED_DOMAINS.keys()) < 1:
        ISSUED_DOMAINS.update({"Genesis": hashlib.sha256("Genesis".encode()).hexdigest()})

    #ISSUED_DOMAINS.append(str(cert.get_subject().commonName))
    #print(ISSUED_DOMAINS)
        
    #pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()))
        
    #ISSUED_DOMAINS.update({str(cert.get_subject().commonName): csr.get_pubkey()})
    ISSUED_DOMAINS.update({domain: pub_key_hash.hexdigest()})
    print(ISSUED_DOMAINS)




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
    global VALIDATORS_LIST
    global VOTES
    global APPROVE_VOTES

    if msg_json['bcaction'] == "issue":
        csr_file = msg_json['filename']
        requestor_name = msg_json['name']

        # Get the last block in the blockchain
        folder_path = './blockchain/*'
        #file_type = r'\*txt'
        files = glob.glob(folder_path)
        latest_block = max(files, key=os.path.getctime)

        # Get the hash of the last block
        sha256hasher = FileHash('sha256')
        latest_block_hash = sha256hasher.hash_file(latest_block)
        latest_block_hash_int = int(latest_block_hash, 16)

        print("last block hash: {}".format(latest_block_hash))
        print("hash % {}: {}".format(len(VALIDATORS_LIST), latest_block_hash_int % len(VALIDATORS_LIST)))

        selected_val = (latest_block_hash_int % len(VALIDATORS_LIST)) + 1
        print("Validator{} has been selected to issue certificate".format(selected_val))

        # Select validator to issue certificate
        #if (block_hash_int % VAL_NUM) == (VAL_NUM - 1):
        if selected_val == VAL_NUM:
            # Validation logic 
            f_csr = open(csr_file, 'r')
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, f_csr.read())
            pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()))
            f_csr.close()

            if csr.get_subject().commonName not in ISSUED_DOMAINS.keys():
                if pub_key_hash.hexdigest() not in ISSUED_DOMAINS.values():
                    issue_cert(csr_file, requestor_name, latest_block_hash)
                    block_hd = block_header(requestor_name, latest_block)
            
                    #print("block header type: {}".format(type(block_hd)))
                    json_object = json.dumps(block_hd, indent=4)
 
                    # new proposed block
                    ###f = open("block" + block_hd["Block_num"] + ".json", "w")
                    ###f.write(json_object)
                    ###f.close()

                    time.sleep(3)

                    # send the header and certificate to other validators for attestation
                    for val in VALIDATORS_LIST:
                        if val != NAME:
                            unicast(val, block_hd, requestor_name + '.crt', 'attest')
                            time.sleep(1)

                else:
                    print("Invalid request, there is an existing Certificate in the blockchain with the key: {}".format(pub_key_hash.hexdigest()))
            else:
                print("Invalid request, {} has an existing Certificate in the blockchain".format(csr.get_subject().commonName))

    

    elif msg_json['bcaction'] == "req_cert":
        unicast(msg_json['name'], 'Sending Certificate', NAME + '.crt', 'add_key')

    elif msg_json['bcaction'] == "add_key":
        add_validator_key(msg_json['name'])

    elif msg_json['bcaction'] == "attest":
        # Validate new certificate
        vote = False
        original_header_timestamp = msg_json['message']['Timestamp']
        #print("Original header: ")
        #print(original_header)
        cert_file = msg_json['filename']
        issuer_validator = msg_json['name']
        f_issuer_cert = open(issuer_validator + ".crt", "r")
        issuer_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f_issuer_cert.read())
        #issuer_pub_key = issuer_cert.get_pubkey()
        f_issuer_cert.close()
       
        f_cert = open(cert_file, 'r')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f_cert.read())
        pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()))
        f_cert.close()

        store = crypto.X509Store()
        store.add_cert(issuer_cert)
        store_context = crypto.X509StoreContext(store, cert)

        try:
            store_context.verify_certificate()
            print("Valid signature")

            if cert.get_subject().commonName not in ISSUED_DOMAINS.keys():
                if pub_key_hash.hexdigest() not in ISSUED_DOMAINS.values():
                    print("valid certificate")

                    # Validate new block
                    requestor_name = msg_json['filename'][:-4]
                    # Get the last block in the blockchain
                    folder_path = './blockchain/*'
                    files = glob.glob(folder_path)
                    sha256hasher = FileHash('sha256')
                    latest_block = max(files, key=os.path.getctime)
                    latest_block_hash = sha256hasher.hash_file(latest_block)
                    domain = str(cert.get_subject().commonName)

                    update_dicts(requestor_name, latest_block_hash, pub_key_hash, domain)

                    block_hd = block_header(requestor_name, latest_block)

                    print("calculated block header: {}".format(type(block_hd)))
                    print(block_hd)
                    print("received block header: {}",format(type(msg_json['message'])))
                    print(msg_json['message'])

                    block_hd['Timestamp'] = ''
                    block_recvd = msg_json['message']
                    block_recvd['Timestamp'] = ''
                    ##### Validate without timestap!!!!
                    
                    if block_hd == block_recvd:
                        print("same block header, valid block")
                        block_recvd['Timestamp'] = original_header_timestamp
                        vote = True
                        APPROVE_VOTES += 1
                    else:
                        print("Invalid block")
                else:
                    print("Invalid request, there is an existing Certificate in the blockchain with the key: {}".format(pub_key_hash.hexdigest()))
            else:
                print("Invalid request, {} has an existing Certificate in the blockchain".format(cert.get_subject().commonName))


        except Exception as error:
            print("Invalid certificate signature")
            print(error)

        #send_validators(vote)
        msg = [vote, block_recvd]
        time.sleep(3)
        for val in VALIDATORS_LIST:
            if val != NAME:
                unicast(val,msg,'','vote')   
                time.sleep(VAL_NUM)

    elif msg_json['bcaction'] == "vote":
        vote = msg_json['message'][0]
        header = msg_json['message'][1]
        VOTES[msg_json['name']] = vote

        # PBFT fault tolerance metrics
        # consensus is achieved if and only if the number of votes is greater or 
        # equal than 2f+1, where f=(t-1)/3, and t is the number of validators in the blockchain network

        ft = (len(VALIDATORS_LIST) - 1) / 3
        vote_threshold = math.trunc((2 * ft) + 1)
        
        if vote == True:
            APPROVE_VOTES += 1

        if APPROVE_VOTES >= vote_threshold:
            # adding block to blockchain
            json_object = json.dumps(header, indent=4)
            f = open("./blockchain/block" + header["Block_num"] + ".json", "w")
            f.write(json_object)
            f.close()
            APPROVE_VOTES = 0
            print("Consensus achieved, bock added to blockchain successfully")

        else:
            print("Not enough approval votes to add block")



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


def block_header(requestor_name, latest_block):
    global CERTS_HASH_LIST
    global VALIDATORS_LIST
    global ISSUED_DOMAINS

    header = {
	    "Block_num": "",
	    "Timestamp": "",
	    "Previous_block_hash": "",
	    "Certificates_Merkle_root": "",
	    "Transactions_Merkle_root": "",
    	"Validator_Merkle_root": "",
	    "Issued_domains_Merkle_root": "",
	    "Current_Cert_Merkle_proof": "",
        "Current_Cert_Hash": ""
    }

    # Determine block number
    f = open(latest_block)
    latest_block_content = json.load(f)
    new_block_num = int(latest_block_content["Block_num"]) + 1
    header["Block_num"] = str(new_block_num)
    f.close()

    # Determine timestamp
    header["Timestamp"] = str(time.time())

    # Determine previous block hash
    sha256hasher = FileHash('sha256')
    header["Previous_block_hash"] = sha256hasher.hash_file(latest_block)

    # Determine Certificates hash list Merkle root
    #if len(CERTS_HASH_LIST) >= 2:
    #    certs_mtree = MerkleTree(CERTS_HASH_LIST)
    certs_mtree = MerkleTree(CERTS_HASH_LIST)
    #print(mtree)
    #mroot =  mtree.root.hex()
    #print("mroot: {}".format(mroot))
    header["Certificates_Merkle_root"] = certs_mtree.root.hex()

    # Determine validators list Merkle root
    validators_mtree = MerkleTree(VALIDATORS_LIST)
    header["Validator_Merkle_root"] = validators_mtree.root.hex()

    # Determine Issued domains list Merkle root
    domains_mtree = MerkleTree(list(ISSUED_DOMAINS.keys()))
    header["Validator_Merkle_root"] = domains_mtree.root.hex()

    # Determine current issued certificate proof
    cert_hash = sha256hasher.hash_file(requestor_name + ".crt")
    print("Cert hash: {}".format(cert_hash))
    print("Cert hash list: {}".format(CERTS_HASH_LIST))
    certproof = certs_mtree.proof(cert_hash)
    header["Current_Cert_Merkle_proof"] = str(certproof)

    # Determine current cert hash
    header["Current_Cert_Hash"] = cert_hash

    return header
    

    


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
    CERTS_HASH_LIST = []
    ISSUED_DOMAINS = {}
    VOTES = {}
    APPROVE_VOTES = 0
    
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    
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
