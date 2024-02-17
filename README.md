Python3 scripts for each blockchain node under the "nodes"folder

# Blockchain based PKI prototype in Python
Decentralized PKI architecture based on blockchain, replacing the Certificate Authorities with decentralized validator nodes in the blockchain, eliminating single points of failure and the need of a trusted third-party.

Certificates issued by blockchain validator nodes in lieu of Certificate Authorities, and added to the blockchain, allowing for decentralized nodes validation without the need of trustworthy root CAs and pre-storage of trusted CAs certificates in TLS clients.

Other nodes validate the certificates before getting added to the blockchain to prevent fraudulent certificates (block attestation).

Certificate validation made by verifying its membership in the blockchain in lieu of the CA digital signature.

Three node types as blockchain participants: Requestors, Validators, Clients.

Alternative PoS consensus mechanism where all validator nodes join the blockchain with the same amount of tokens and the selection is randomized, not weighted based on tokens amount to decentralize the validator selection in the traditional PoS mechanism. The proposed consensus mechanism is a combination of Proof of Stake (PoS) with Practical Byzantine Fault Tolerance (PBFT) used as follows:

PoS: used to select the next validator to issue the certificate and propose the new block. To be able to join the blockchain network as a validator, a subject or organization needs to “stake” a fixed amount of tokens, and the next validator is selected pseudo-randomly. In contrast with existing PoS blockchains where the nodes can stake different amount of tokens and with the greater number of tokens, they get more chances to be elected to propose the new block; in this proposal all nodes stake the same amount, and all get the same chances to propose the next block to make it truly decentralized.
 
PBFT: used to agree on the validity of the new certificate and block by attesting the new block proposal and the new block is added if and only if the number of approval votes is greater or equal than 2f+1, where f=(t-1)\/3, and t is the number of validators in the blockchain network (Tarooni & Gehrmann, 2021).

The prototype is implemented through several Python3 processes executed in the same VM, executing in their corresponding folders, there is a python script for a messaging server handling the communications between the different python processes, and a script for each node in the blockchain (validators, requestors and clients). A minimum of 3 validators is required to achieve consensus and tolerate 1 faulty/rogue validator.


# Blockchain nodes
Requestor nodes:

  Light nodes.
  Digital Certificate owners that authenticate to a service or client through the valid certificate. These nodes generate their public/private key pairs and send the certificate request through standard x509   Certificate Signing Request (CSR) to the blockchain network.

  Send a certificate request fee to the validator node that issues the certificate.
  
  Stores: 
Last block of the blockchain
Digital certificate
Block where the certificate hash was added to the blockchain.
Wallet information

  Executes:
Requests certificate through CSR to the blockchain network
Receives certificate and verifies legitimacy by confirming the issuer and its membership in the blockchain via Merkle proof sent by the validator.

Validator nodes: 

Full nodes.

Responsible for maintaining a full copy of the blockchain and maintain its transparency.

Digital Certificates issuers. Validator nodes will receive the CSRs through the blockchain network and via the consensus mechanism, a validator will be chosen to issue the certificate by:
Validating the information provided by the requestor, 
Validating domain ownership
Validating no other certificates have been issued for the same domain.
Validating the presented public key is unique.
Issue the certificate and send it back to the requestor.
Propose and add new blocks to the blockchain:
Assemble headers with the most updated Merkle tree roots.
Add the issued digital Certificate hash to the block.
Add the certificate issuance fee transaction to the block.
Attest new block proposal through PBFT consensus:
Validate block headers.
Validate block is issued by a legitimate validator in the blockchain.
Validate digital certificate by performing the same data validations as the issuer.
Provide Merkle proofs to clients.
Generate Merkle proof for a specific certificate hash with the most recent Merkle root and sends it to the client for verification.

Stores:
Full copy of the blockchain
Wallet information
Issued domains dictionary: not part of the blockchain, but a local copy so the validator can dynamically modify and search for the domains with a valid certificate in the blockchain. The dictionary is not part of the blockchain, but the Merkle root of the dictionary is part of the block header.
Certificate requests queue: not part of the blockchain, local copy of the requests to be processed (similar to the pool of unconfirmed transactions in a transaction-based blockchain), this queue is modified dynamically as certificates are issued.
Validator nodes dictionary: not part of the blockchain, local copy to keep control of the active validators in the network. The dictionary is not part of the blockchain, but the Merkle root of the dictionary is part of the block header.
List of the issued certificates list: not part of the blockchain, local copy to dynamically build the Merkle trees, it is kept out of the blockchain to be dynamic and cannot be append-only to remove hashes as part of the revocation process. The Merkle root is added in the block header, and it is used by the clients and requestors to validate the certificate membership in the blockchain. The Merkle tree (this the Merkle root) of the entire blockchain changes upon new block addition, but the clients and requestors just need the last block to validate membership. –- Any blockchain is dynamic in nature, and every time a new block gets added all nodes store a local copy of either the full blockchain or just the headers in case of the light nodes.

Executes: 
Certificate Issuance
Attestation on new block proposals
Revocation
Merkle proof generation

Client nodes.

Light nodes

Authenticates the peer server or entity (requestor node) through their valid certificate in the blockchain.
Participate in the blockchain network for certificate validation. During TLS handshake, client receives the server’s certificate, and in lieu of validating the issuer’s signature and comparing against the trusted root CAs store, the client requests a Merkle proof to the blockchain network. Validators generate the proof and send it back to the client, then the client can validate certificate membership in the blockchain against the most recent Merkle root.

Stores:
Last block in the blockchain

Executes:
Receives server’s certificate during handshake.
Requests Merkle proof for the given certificate to the validators
Validates certificate membership in the blockchain with the provided Merkle proof against the Merkle root stored in the last block in the blockchain (local copy stored in the client)

***Messaging server

Auxiliary process to handle the communications in the local environment to emulate a peer-to-peer network.



# Functions
1) Certificate issuance
2) Block attestation and consensus
3) Certificate revocation
4) Certificate validation (membership in the blockchain)
5) Merkle proof generation
