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
from colorama import Fore, Back, Style
from urllib import request

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
  
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
  
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))
  
def prLightPurple(skk): print("\033[94m {}\033[00m" .format(skk))
  
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk))
  
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
  
def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))
 
def prBlack(skk): print("\033[98m {}\033[00m" .format(skk))

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
                prCyan('Name: {}'.format(msg_json['name']))

            elif msg_json['net_action'] == 'new_node':
                if msg_json['client_name'] != NAME:
                    prCyan('{} has joined the network'.format(msg_json['client_name']))

                    if msg_json['validator'] == True:
                        if VALIDATORS_LIST:
                            #print("Control point printing validators list: {}".format(VALIDATORS_LIST))
                            if msg_json['client_name'] not in VALIDATORS_LIST:
                                time.sleep(VAL_NUM)
                                prYellow("adding {} to the validators list".format(msg_json['client_name']))
                                VALIDATORS_LIST.append(msg_json['client_name'])
                                req_cert(msg_json['client_name'])

                                


            elif msg_json['net_action'] == 'confirm_list':
                BCNETWORKNUM = msg_json['real_clients_num']
                BCNETWORKNODES = msg_json['real_clients_name']
                VALIDATORS_LIST = msg_json['validators']                

                #print(BCNETWORKNUM)
                prCyan("Blockchain network nodes: {}".format(BCNETWORKNODES))
                prCyan("Validators list: {}". format(VALIDATORS_LIST))
                

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
        #print("\n")
        #print(bytes_read)
        #print("\n")
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
    prGreen("Validator Certificate generated successfully")

    # Save private key
    f_key =  open(NAME+'.key', "wt")
    f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, own_key).decode("utf-8"))
    f_key.close()
    prGreen("Validator Key generated successfully")

    # add itself to the vaidators dictionary
    #pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, own_key).decode("utf-8")
    pub_key = own_cert.get_pubkey()
    VALIDATORS_DICT[NAME] = pub_key
    VALIDATORS_LIST.append(NAME)

def issue_cert(csr_file, requestor_name):
    global CERTS_HASH_LIST
    global ISSUED_DOMAINS
    global PREV_ISSUED_DOMAINS
    global PREV_CERTS_HASH_LIST

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

    #PREV_CERTS_HASH_LIST = CERTS_HASH_LIST
    backup_certs()
    #PREV_ISSUED_DOMAINS = ISSUED_DOMAINS
    backup_domains()
    update_dicts(requestor_name, pub_key_hash, domain)


    prGreen('Certificate created successfully')


def update_dicts(requestor_name, pub_key_hash, domain):
    # add cert hash to the hash list
    sha256hasher = FileHash('sha256')
    # Get the last block in the blockchain
    folder_path = './blockchain/*'
    #file_type = r'\*txt'
    files = glob.glob(folder_path)
    latest_block = max(files, key=os.path.getctime)

    # Get the hash of the last block
    latest_block_hash = sha256hasher.hash_file(latest_block)

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
    prYellow('Extracting public key for {}'.format(cert))
    f = open(cert, "r")
    pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
    f.close()
    return pub_key

def req_cert(name):
    unicast(name, 'Requesting Certificate', '', 'req_cert')

def generate_challenge():
    rand_list = []
    rand_list.append(random.randint(50000000, 100000000))
    rand_list.append(random.randint(50000000, 100000000))
    rand_list.append(random.randint(50000000, 100000000))
    rand_list.append(random.randint(50000000, 100000000))
    rand_list.append(random.randint(50000000, 100000000))

    f = open("challenge.txt", "w")
    for r in rand_list:
        f.write(str(r) + "\n")
    f.close()

def dcv(common_name):
    res = False
    remote_url = 'http://' + common_name + ':8080/challenge'
    # Define the local filename to save data
    local_file = 'challenge_copy.txt'
    # Download remote and save locally
    prYellow("requesting challenge file to {}".format(remote_url))
    try:
        request.urlretrieve(remote_url, local_file)
        # Get the hash of the original challenge
        sha256hasher = FileHash('sha256')
        orig_chall_hash = sha256hasher.hash_file("challenge.txt")
        # Get the hash of the received challenge
        recv_chall_hash = sha256hasher.hash_file(local_file)
        if orig_chall_hash == recv_chall_hash:
            res = True
    except:
        prRed("Challenge file not fount in: {}".format(remote_url))

    
    return res


#####################################################################################################################################
### Blockchain handling functions
#####################################################################################################################################
    
def blockchain_action(msg_json):
    global VALIDATORS_LIST
    global VOTES
    global APPROVE_VOTES
    global SELECTED
    global PREV_CERTS_HASH_LIST
    global PREV_ISSUED_DOMAINS
    global ISSUED_DOMAINS
    global CERTS_HASH_LIST


    if msg_json['bcaction'] == "req_cert_issuance":
        # Get the last block in the blockchain
        folder_path = './blockchain/*'
        #file_type = r'\*txt'
        files = glob.glob(folder_path)
        latest_block = max(files, key=os.path.getctime)
        f = open(latest_block, "r")
        block_data = f.read()
        f.close()
        block_json = json.loads(block_data)
        print("Number of files: {}".format(len(files)))
        print("Last block numeber: {}".format(block_json['Block_num']))
        if len(files) != int(block_json['Block_num']):
            prRed("Blockchain tampered, Block {} was modified".format(block_json['Block_num']))
            #broadcast("Aborting...", "", "abort")
            #time.sleep(7)
            #for val in VALIDATORS_LIST:
            #    if val != NAME:
            #        unicast(val, "Aborting...", "", 'abort')
            #        time.sleep(1)
        else:

            # Get the hash of the last block
            sha256hasher = FileHash('sha256')
            latest_block_hash = sha256hasher.hash_file(latest_block)
            latest_block_hash_int = int(latest_block_hash, 16)

            prYellow("last block hash: {}".format(latest_block_hash))
            prYellow("hash % {}: {}".format(len(VALIDATORS_LIST), latest_block_hash_int % len(VALIDATORS_LIST)))

            selected_val = (latest_block_hash_int % len(VALIDATORS_LIST)) + 1
            prYellow("Validator{} has been selected to issue certificate".format(selected_val))

            # Select validator to issue certificate
            #if (block_hash_int % VAL_NUM) == (VAL_NUM - 1):
            if selected_val == VAL_NUM:
                SELECTED = True
                generate_challenge()
                unicast(msg_json['name'], "dcv challenge", "challenge.txt", "challenge")

    elif msg_json['bcaction'] == "issue":
        csr_file = msg_json['filename']
        requestor_name = msg_json['name']

        f_csr = open(csr_file, 'r')
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, f_csr.read())
        pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()))
        f_csr.close()

        prGreen("csr loaded")

        if csr.get_subject().commonName not in ISSUED_DOMAINS.keys():
            prGreen("valid subject common name")
            if pub_key_hash.hexdigest() not in ISSUED_DOMAINS.values():
                prGreen("valid public key")
                print(csr.get_subject().commonName)
                if dcv(csr.get_subject().commonName):
                    prGreen("Domain Control Validation successful, issuing certificate...")
                    issue_cert(csr_file, requestor_name)
                    # Get the last block in the blockchain
                    folder_path = './blockchain/*'
                    #file_type = r'\*txt'
                    files = glob.glob(folder_path)
                    latest_block = max(files, key=os.path.getctime)
                    if validate_bc():
                        prGreen("Valid blockchain")
                        block_hd = block_header(requestor_name, latest_block)
            
                        #print("block header type: {}".format(type(block_hd)))
                        json_object = json.dumps(block_hd, indent=4)
 
                        # new proposed block
                        ###f = open("block" + block_hd["Block_num"] + ".json", "w")
                        ###f.write(json_object)
                        ###f.close()
                        APPROVE_VOTES += 1
                        VOTES[NAME] = True
                        time.sleep(3)

                        # send the header and certificate to other validators for attestation
                        for val in VALIDATORS_LIST:
                            if val != NAME:
                                unicast(val, block_hd, requestor_name + '.crt', 'attest')
                                time.sleep(1)
                    else:
                        prRed("Invalid Blockchain, aborting certificate issuance")
                else:
                    prRed("Domain Control Validation failed")
            else:
                prRed("Invalid request, there is an existing Certificate in the blockchain with the key: {}".format(pub_key_hash.hexdigest()))
        else:
            prRed("Invalid request, {} has an existing Certificate in the blockchain".format(csr.get_subject().commonName))

        '''
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
            SELECTED = True
            # Validation logic 
            f_csr = open(csr_file, 'r')
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, f_csr.read())
            pub_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()))
            f_csr.close()

            if csr.get_subject().commonName not in ISSUED_DOMAINS.keys():
                if pub_key_hash.hexdigest() not in ISSUED_DOMAINS.values():
                    if dcv(csr.get_subject().commonName):
                        print("Domain Control Validation successful, issuing certificate...")
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
                        print("Domain Control Validation failed")
                else:
                    print("Invalid request, there is an existing Certificate in the blockchain with the key: {}".format(pub_key_hash.hexdigest()))
            else:
                print("Invalid request, {} has an existing Certificate in the blockchain".format(csr.get_subject().commonName))
        '''
    

    elif msg_json['bcaction'] == "req_cert":
        unicast(msg_json['name'], 'Sending Certificate', NAME + '.crt', 'add_key')

    elif msg_json['bcaction'] == "add_key":
        add_validator_key(msg_json['name'])

    elif msg_json['bcaction'] == "attest":
        # Validate new certificate
        vote = False
        VOTES[NAME] = False
        VOTES[msg_json['name']] = True
        APPROVE_VOTES += 1
        original_header_timestamp = msg_json['message']['Timestamp']
        #print("Original header: ")
        #print(original_header)
        cert_file = msg_json['filename']
        issuer_validator = msg_json['name']
        f_issuer_cert = open(issuer_validator + ".crt", "r")
        issuer_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f_issuer_cert.read())
        issuer_pub_key = issuer_cert.get_pubkey()
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
            prGreen("Valid signature")

            if issuer_pub_key.to_cryptography_key() == VALIDATORS_DICT[issuer_validator].to_cryptography_key():
                prGreen("Issuer validator key validated matches the key stored in dictionary")

                if cert.get_subject().commonName not in ISSUED_DOMAINS.keys():
                    if pub_key_hash.hexdigest() not in ISSUED_DOMAINS.values():
                        prGreen("valid certificate")

                        # Validate new block
                        requestor_name = msg_json['filename'][:-4]
                        # Get the last block in the blockchain
                        folder_path = './blockchain/*'
                        files = glob.glob(folder_path)
                        sha256hasher = FileHash('sha256')
                        latest_block = max(files, key=os.path.getctime)
                        latest_block_hash = sha256hasher.hash_file(latest_block)
                        domain = str(cert.get_subject().commonName)

                        #PREV_CERTS_HASH_LIST = CERTS_HASH_LIST
                        backup_certs()
                        #PREV_ISSUED_DOMAINS = ISSUED_DOMAINS
                        backup_domains()

                        update_dicts(requestor_name, pub_key_hash, domain)

                        block_hd = block_header(requestor_name, latest_block)

                        #prYellow("calculated block header: {}".format(type(block_hd)))
                        print("\n")
                        print(block_hd)
                        print("\n")
                        #prYellow("received block header: {}".format(type(msg_json['message'])))
                        print(msg_json['message'])
                        print("\n")

                        block_hd['Timestamp'] = ''
                        block_recvd = msg_json['message']
                        block_recvd['Timestamp'] = ''
                        ##### Validate without timestap!!!!
                    
                        if validate_bc():
                            prGreen("Valid blockchain")
                            if block_hd == block_recvd:
                                prGreen("same block header, valid block")
                                block_recvd['Timestamp'] = original_header_timestamp
                                vote = True
                                APPROVE_VOTES += 1
                                VOTES[NAME] = True
                            else:
                                prRed("Invalid block")
                                print("\n")
                                print("Calculated header:")
                                print(block_hd)
                                print("\n")
                                print("Block received:")
                                print(block_recvd)
                        else:
                            prRed("Invalid blockchain, hashes don't match")
                    else:
                        prRed("Invalid request, there is an existing Certificate in the blockchain with the key: {}".format(pub_key_hash.hexdigest()))
                else:
                    prRed("Invalid request, {} has an existing Certificate in the blockchain".format(cert.get_subject().commonName))
            else:
                prRed("issuer key does not match validator key in dict")


        except Exception as error:
            prRed("Invalid certificate signature")
            prRed(error)

        #send_validators(vote)
        
        msg = [vote, block_recvd, requestor_name]
        time.sleep(3)
        for val in VALIDATORS_LIST:
            if val != NAME:
                unicast(val,msg,'','vote')   
                time.sleep(VAL_NUM)

    elif msg_json['bcaction'] == "vote":
        vote = msg_json['message'][0]
        header = msg_json['message'][1]
        requestor = msg_json['message'][2]
        VOTES[msg_json['name']] = vote
        consensus = False

        # PBFT fault tolerance metrics
        # consensus is achieved if and only if the number of votes is greater or 
        # equal than 2f+1, where f=(t-1)/3, and t is the number of validators in the blockchain network

        ft = (len(VALIDATORS_LIST) - 1) / 3
        vote_threshold = math.trunc((2 * ft) + 1)
        
        if vote == True:
            APPROVE_VOTES += 1

        if APPROVE_VOTES >= vote_threshold and len(VALIDATORS_LIST) > 2:
            # adding block to blockchain
            json_object = json.dumps(header, indent=4)
            f = open("./blockchain/block" + header["Block_num"] + ".json", "w")
            f.write(json_object)
            f.close()
            
            consensus = True
            print("Number of votes on counter: {}".format(APPROVE_VOTES))
            print("Number of votes on dict: {}".format(len(VOTES.keys())))
            print(VOTES)
            APPROVE_VOTES = 0
            VOTES.clear()
            prGreen("Consensus achieved, bock added to blockchain successfully")

            if SELECTED == True:
                #print("Sending certificate to requestor")
                #unicast(requestor, header, requestor + ".crt","recv_cert")
                time.sleep(7)
                prYellow("Sending new block to the network")
                time.sleep(1)
                broadcast(header, "","recv_block")
                SELECTED = False
           #else:
            #    print("Not selected")

            '''
            if requestor != "":
                if SELECTED == True:
                    #print("Sending certificate to requestor")
                    #unicast(requestor, header, requestor + ".crt","recv_cert")
                    time.sleep(3)
                    print("Sending new block to the network")
                    broadcast(header, "","recv_block")
                    SELECTED = False
                else:
                    print("Not selected")
            else:
                print("Requestor empty")
            '''

        else:
            prYellow("Not enough approval votes to add block")
            print("Number of votes on counter: {}".format(APPROVE_VOTES))
            print("Number of votes on dict: {}".format(len(VOTES.keys())))
            print(VOTES)
            if len(VOTES.keys()) == len(VALIDATORS_DICT.keys()):
                prRed("All votes received, consensus was not achieved")
                print("Current data structure:")
                prRed(ISSUED_DOMAINS)
                prRed(CERTS_HASH_LIST)
                #ISSUED_DOMAINS = PREV_ISSUED_DOMAINS
                restore_domains()
                #CERTS_HASH_LIST = PREV_CERTS_HASH_LIST
                restore_certs()
                prGreen("Data restored to previous state")
                prYellow(ISSUED_DOMAINS)
                prYellow(CERTS_HASH_LIST)


    elif msg_json['bcaction'] == "issued_cert":
        unicast(msg_json['name'], "Sending issued certificate", msg_json['name'] + ".crt","recv_cert")

    elif msg_json['bcaction'] == "confirm_cert":
        folder_path = './blockchain/*'
        files = glob.glob(folder_path)
        sha256hasher = FileHash('sha256')
        latest_block = max(files, key=os.path.getctime)

        f = open(latest_block, "r")
        block_data = f.read()
        f.close()
        block_json = json.loads(block_data)

        prYellow("Sending new block to the network")
        broadcast(block_json, "","recv_block")

    elif msg_json['bcaction'] == "req_Merkle":
        Merkle_proof = []
        cert_hash = msg_json["message"][0]
        owner = msg_json["message"][1]
        prYellow("Generating Merkle proof for: {}".format(cert_hash))
        certs_mtree = MerkleTree(CERTS_HASH_LIST)
        try:
            proof = certs_mtree.proof(cert_hash)
        except:
            proof = "Invalid"
        Merkle_proof.append(str(CERTS_HASH_LIST))
        Merkle_proof.append(str(proof))
        Merkle_proof.append(owner)
        time.sleep(1)
        unicast(msg_json["name"], Merkle_proof, "", "recv_proof")

    elif msg_json['bcaction'] == "revoke":
        ### insert call to DCV
        requestor_name = msg_json['name']
        cert_file = msg_json['filename']

        sha256hasher = FileHash('sha256')

        # Get the last block in the blockchain
        folder_path = './blockchain/*'
        #file_type = r'\*txt'
        files = glob.glob(folder_path)
        latest_block = max(files, key=os.path.getctime)
        f = open(latest_block, "r")
        block_data = f.read()
        f.close()
        block_json = json.loads(block_data)
        print("Number of files: {}".format(len(files)))
        print("Last block numeber: {}".format(block_json['Block_num']))
        if len(files) != int(block_json['Block_num']):
            prRed("Blockchain tampered, Block {} was modified".format(block_json['Block_num']))
            #broadcast("Aborting...", "", "abort")
            #time.sleep(7)
            #for val in VALIDATORS_LIST:
            #    if val != NAME:
            #        unicast(val, "Aborting...", "", 'abort')
            #        time.sleep(1)

        else:
            latest_block_hash = sha256hasher.hash_file(latest_block)
            latest_block_hash_int = int(latest_block_hash, 16)

            prYellow("last block hash: {}".format(latest_block_hash))
            prYellow("hash % {}: {}".format(len(VALIDATORS_LIST), latest_block_hash_int % len(VALIDATORS_LIST)))

            selected_val = (latest_block_hash_int % len(VALIDATORS_LIST)) + 1
            prYellow("Validator{} has been selected to revoke certificate".format(selected_val))

            if selected_val == VAL_NUM:
                SELECTED = True
                print("Issued domains dict: {}".format(ISSUED_DOMAINS))
                f_cert = open(cert_file, 'r')
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f_cert.read())
                f_cert.close()

                if validate_bc():
                    prGreen("Valid blockchain")
                    if cert.get_subject().commonName in ISSUED_DOMAINS.keys():
                        #PREV_ISSUED_DOMAINS = ISSUED_DOMAINS
                        backup_domains()
                        del ISSUED_DOMAINS[cert.get_subject().commonName]
                        if len(ISSUED_DOMAINS.keys()) < 2:
                            ISSUED_DOMAINS.update({"Genesis2": hashlib.sha256("Genesis2".encode()).hexdigest()})
                        prGreen("domain deleted from dictionary")

                        cert_hash = sha256hasher.hash_file(cert_file)
                        if cert_hash in CERTS_HASH_LIST:
                            #PREV_CERTS_HASH_LIST = CERTS_HASH_LIST
                            backup_certs()
                            CERTS_HASH_LIST.remove(cert_hash)
                    
                            # need at least 2 elements in list to build the merkle tree, if list is empty, add the latest block hash as the first hash in list
                            if len(CERTS_HASH_LIST) < 2:
                                CERTS_HASH_LIST.append(latest_block_hash)
                    
                            prGreen("hash list updated successfully")

                            block_hd = block_header("", latest_block)
                            APPROVE_VOTES += 1
                            VOTES[NAME] = True
                            time.sleep(3)
                            # send the header and certificate to other validators for attestation
                            msg = []
                            msg.append(block_hd)
                            msg.append(cert.get_subject().commonName)
                            msg.append(cert_hash)
                            for val in VALIDATORS_LIST:
                                if val != NAME:
                                    unicast(val, msg, "", 'attest_revocation')
                                    time.sleep(1)
                        else:
                            prRed("Certificate hash not found on Certificates Hash List")
                        
                    else:
                        prRed("{} not found on valid domains dictionary".format(requestor_name))
                    
                else:
                    prRed("Invalid blockchain, hashes don't match")


    elif msg_json['bcaction'] == "abort":
        restore_certs()
        restore_domains()
        prYellow("Data restored")
    
    elif msg_json['bcaction'] == "attest_revocation":
        vote = False
        VOTES[NAME] = False
        VOTES[msg_json['name']] = True
        APPROVE_VOTES += 1
        hdr = msg_json['message'][0]
        original_header_timestamp = hdr['Timestamp']
        domain = msg_json['message'][1]
        cert_hash = msg_json['message'][2]

        sha256hasher = FileHash('sha256')

        # Get the last block in the blockchain
        folder_path = './blockchain/*'
        #file_type = r'\*txt'
        files = glob.glob(folder_path)
        latest_block = max(files, key=os.path.getctime)
        latest_block_hash = sha256hasher.hash_file(latest_block)

        if domain in ISSUED_DOMAINS.keys():
            #PREV_ISSUED_DOMAINS = ISSUED_DOMAINS
            backup_domains()

            del ISSUED_DOMAINS[domain]
            if len(ISSUED_DOMAINS.keys()) < 2:
                ISSUED_DOMAINS.update({"Genesis2": hashlib.sha256("Genesis2".encode()).hexdigest()})
                prGreen("domain deleted from dictionary")

            #cert_hash = sha256hasher.hash_file(cert_file)
            if cert_hash in CERTS_HASH_LIST:
                #PREV_CERTS_HASH_LIST = CERTS_HASH_LIST
                backup_certs()
                CERTS_HASH_LIST.remove(cert_hash)
                # need at least 2 elements in list to build the merkle tree, if list is empty, add the latest block hash as the first hash in list
                if len(CERTS_HASH_LIST) < 2:
                    CERTS_HASH_LIST.append(latest_block_hash)
                prGreen("hash list updated successfully")
            else:
                prRed("Certificate hash not found on list")
        else:
            prRed("Domain not found on issued certificates dictionary")

        block_hd = block_header("", latest_block)
        block_hd['Timestamp'] = ''
        block_recvd = msg_json['message'][0]
        block_recvd['Timestamp'] = ''

        if validate_bc():
            prGreen("Valid blockchain")
            if block_hd == block_recvd:
                prGreen("same block header, valid block")
                block_recvd['Timestamp'] = original_header_timestamp
                vote = True
                APPROVE_VOTES += 1
                VOTES[NAME] = True
            else:
                prRed("Invalid block")
                print("\n")
                print("Calculated header:")
                print(block_hd)
                print("\n")
                print("Block received:")
                print(block_recvd)
        else:
            prRed("Invalid blockchain, hashes don't match")

        msg = [vote, block_recvd, ""]
        time.sleep(3)
        for val in VALIDATORS_LIST:
            if val != NAME:
                unicast(val,msg,'','vote')   
                time.sleep(VAL_NUM)

def backup_certs():
    global PREV_CERTS_HASH_LIST
    global CERTS_HASH_LIST

    PREV_CERTS_HASH_LIST.clear()
    for cert in CERTS_HASH_LIST:
        PREV_CERTS_HASH_LIST.append(cert)


def backup_domains():
    global PREV_ISSUED_DOMAINS
    global ISSUED_DOMAINS

    PREV_ISSUED_DOMAINS.clear()
    for dom in ISSUED_DOMAINS.keys():
        PREV_ISSUED_DOMAINS[dom] = ISSUED_DOMAINS[dom]

def restore_certs():
    global PREV_CERTS_HASH_LIST
    global CERTS_HASH_LIST

    CERTS_HASH_LIST.clear()
    for cert in PREV_CERTS_HASH_LIST:
        CERTS_HASH_LIST.append(cert)


def restore_domains():
    global PREV_ISSUED_DOMAINS
    global ISSUED_DOMAINS

    ISSUED_DOMAINS.clear()
    for dom in PREV_ISSUED_DOMAINS.keys():
        ISSUED_DOMAINS[dom] = PREV_ISSUED_DOMAINS[dom]


def validate_bc():
    folder_path = './blockchain/*'
    blocks = glob.glob(folder_path)
    first_block = './blockchain/block1.json'
    sha256hasher = FileHash('sha256')

    first_block_hash = sha256hasher.hash_file(first_block)
    prev_hash = first_block_hash

    valid_blockchain = True
    
    for num in range(len(blocks)):
        bl_num = num + 1
        bl = './blockchain/block' + str(bl_num) + '.json'
        prYellow("validating {}".format(bl))
        f = open(bl, "r")
        block_data = f.read()
        f.close()
        block_json = json.loads(block_data)
        #next_block_num = int(block_json['Block_num']) + 1
        #next_block = "block" + str(next_block_num)

        if bl != first_block:
            if block_json['Previous_block_hash'] == prev_hash:
                prGreen("Block {} valid".format(block_json['Block_num']))
                
            else:
                prRed("Block {} hash does not match the block header, Blockchain tampered".format(block_json['Block_num']))
                valid_blockchain = False
                break

        prev_hash = sha256hasher.hash_file(bl)
        prYellow("block hash: {}".format(prev_hash))

    '''
    for bl in blocks:
        prYellow("validating {}".format(bl))
        f = open(bl, "r")
        block_data = f.read()
        f.close()
        block_json = json.loads(block_data)
        #next_block_num = int(block_json['Block_num']) + 1
        #next_block = "block" + str(next_block_num)

        if bl != first_block:
            if block_json['Previous_block_hash'] == prev_hash:
                prGreen("Block {} valid".format(block_json['Block_num']))
                
            else:
                prRed("Block {} hash does not match the block header, Blockchain tampered".format(block_json['Block_num']))
                valid_blockchain = False
                break

        prev_hash = sha256hasher.hash_file(bl)
        prYellow("block hash: {}".format(prev_hash))
        '''

    return valid_blockchain


def add_validator_key(validator_name):
    prYellow("adding keys to the validators dictionary")
    f = open(validator_name + '.crt', "r")
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    pub_key = cert.get_pubkey()
    f.close()
    VALIDATORS_DICT[validator_name] = pub_key
    prGreen("Validator node added successfully")
    print("Validators:")
    print(VALIDATORS_DICT)
    prGreen("ok")


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
    try:
        validators_mtree = MerkleTree(VALIDATORS_LIST)
        header["Validator_Merkle_root"] = validators_mtree.root.hex()
    except:
        prRed("Not enough number of validators...")

    # Determine Issued domains list Merkle root
    domains_mtree = MerkleTree(list(ISSUED_DOMAINS.keys()))
    header["Issued_domains_Merkle_root"] = domains_mtree.root.hex()

    # Determine current issued certificate proof
    if requestor_name != "":
        cert_hash = sha256hasher.hash_file(requestor_name + ".crt")
        prYellow("Cert hash: {}".format(cert_hash))
        prYellow("Cert hash list: {}".format(CERTS_HASH_LIST))
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
    PREV_CERTS_HASH_LIST = []
    ISSUED_DOMAINS = {}
    PREV_ISSUED_DOMAINS = {}
    VOTES = {}
    APPROVE_VOTES = 0
    SELECTED = False
    
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

    prYellow("Checking for other validators...")

    for val in VALIDATORS_LIST:
        prYellow("iterating validators list: {}".format(val))
        if val != NAME:
            prYellow("Adding {} to the dictionary".format(val))
            req_cert(val)
            time.sleep(1)
            #add_validator_key(val)
            #time.sleep(1)
    prGreen("OK")

    #print("Validator:")
    #print(VALIDATORS_DICT)

    #menu()