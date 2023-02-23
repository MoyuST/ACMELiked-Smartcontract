# ACME-liked Smart contract

## background

This project is my capstone project which aims to use blockchain to rebuild the ACME procedures.
In the followings are the relevant notes for this project.

## contents
- [ACME-liked Smart contract](#acme-liked-smart-contract)
  - [background](#background)
  - [contents](#contents)
  - [CA](#ca)
    - [cross-signing](#cross-signing)
    - [cross-certificate](#cross-certificate)
  - [ACME bg info](#acme-bg-info)
    - [berief introduction](#berief-introduction)
    - [PKI](#pki)
    - [ACME/RFC 8555 doc](#acmerfc-8555-doc)
      - [workflow overview:](#workflow-overview)
      - [some notes](#some-notes)
      - [Basic functions server provided:](#basic-functions-server-provided)
      - [Basic entities:](#basic-entities)
      - [Pre-authorization](#pre-authorization)
      - [HTTP challenge](#http-challenge)
      - [DNS Challenge](#dns-challenge)
      - [Possible attacks](#possible-attacks)
    - [MISC](#misc)
  - [IPFS](#ipfs)
    - [content addressing](#content-addressing)
    - [Directed acyclic graphs (DAGs)](#directed-acyclic-graphs-dags)
    - [Distributed hash tables (DHTs)](#distributed-hash-tables-dhts)
    - [how IPFS is applied in Ethereum](#how-ipfs-is-applied-in-ethereum)
  - [Blockchain oracle](#blockchain-oracle)
    - [Oracle problem](#oracle-problem)
    - [Oracle design patterns](#oracle-design-patterns)
    - [Types of Oracles](#types-of-oracles)
    - [Applications oracles in smart contracts](#applications-oracles-in-smart-contracts)
  - [TLS](#tls)
    - [TLS vs SSL](#tls-vs-ssl)
    - [HTTPS](#https)
    - [TLS MISC](#tls-misc)
  - [Certificate](#certificate)

ref links:
- [dataTracker](https://datatracker.ietf.org/)

## CA

### cross-signing

It means one node obtain certificates signed by many CAs. In this case, there may exist multiple paths from root CA to the node.

### cross-certificate

A self-signed root CA can obtain certificates from other CAs.

## ACME bg info

### berief introduction
[ref link](https://www.ietf.org/blog/acme/)
The Automated Certificate Management Environment (ACME) protocal, which is stated
as RFC 8555 (Request for Comments), its an standard which allows the web ownner and CAs
to use automatic procedures to generate digitial certificates.

### PKI
ref links:
- (wiki PKI)[https://en.wikipedia.org/wiki/Public_key_infrastructure]
- (tutorialspoint)[https://www.tutorialspoint.com/cryptography/public_key_infrastructure.htm]

In cryptography, a PKI (public key infrastration) is an arrangement that binds public keys with respective identities of entities (like people and organizations). In simple words, in the PKI system, each public key is associated with an unique identity. This kind of association is guranteed by CAs (certificate authorities).

basic procedures in PKI: 
![pki from wiki](Assets/450px-Public-Key-Infrastructure.svg.png)

### ACME/RFC 8555 doc

[RFC 8555](https://datatracker.ietf.org/doc/rfc8555/)

ACME is a protocol that a CA and an applicant can use to automate the process of verification and certificate issuance.

The only validation the CA is required to perform in the DV issuance process is to verify that the requester has effective control of the **domain** [CABFBR].  The CA is not required to attempt to verify the requester's real-world identity.

terminologies:
Certificate Signing Request (CSR)
JSON Web Signature (JWS)

#### workflow overview:

1. account registration:
```
    Client                                                   Server

    [Contact Information]
    [ToS Agreement]
    [Additional Data]
    Signature                     ------->
                                                        Account URL
                                <-------           Account Object

            [] Information covered by request signatures

                        Account Creation
```
2. certificate issuance:
```
    Client                                                   Server

    [Order]
    Signature                     ------->
                                <-------  Required Authorizations

    [Responses]
    Signature                     ------->

                        <~~~~~~~~Validation~~~~~~~~>

    [CSR]
    Signature                     ------->
                                <-------          Acknowledgement

                        <~~~~~~Await issuance~~~~~~>

    [POST-as-GET request]
    Signature                     ------->
                                <-------              Certificate

            [] Information covered by request signatures

                    Certificate Issuance
```
3. certificate revokation:
```
    Client                                                 Server

    [Revocation request]
    Signature                    -------->

                                <--------                 Result

            [] Information covered by request signatures

                    Certificate Revocation
```
#### some notes
HTTP requests (maybe only used for the challenge) involved must encoded using UTF-8.

(Normal) Communications between client and server are over HTTPS with JWS.

ACME request (from clients) with non-empty body MUST encapsulate their payload in JSON Web Signature (JWS), which is signed by clients' private key.

JSON Web Key (JWK) is used in creation of the new account, which will store the public key used for JWS. After registration, it will use Key ID (kid) to referred to the existed key in the server.

Anti-replay attack: server will add a nounce in response and client will reply with nounce in the protected field. Server will renew the nounce when sending an error message. The nounce can be generated in a pool.

An ACME request can contain many identifiers for certificate issuing.

For key rollover (change keys), the ACME client needs to send a request contains signatures of both old and new keys.

No way to reactivate an account.

After client finishs one challenge, it will send an request with empty payload to the challenge link. 

The challenge is finished when one of the challenge is finished.

The ACME client must use different key pairs for account and certificate (used in CSR).

#### Basic functions server provided:

    +------------+--------------------+
    | Field      | URL in Value       |
    +------------+--------------------+
    | newNonce   | New nonce          |
    |            |                    |
    | newAccount | New account        |
    |            |                    |
    | newOrder   | New order          |
    |            |                    |
    | newAuthz   | New authorization  |
    |            |                    |
    | revokeCert | Revoke certificate |
    |            |                    |
    | keyChange  | Key change         |
    +------------+--------------------+

A GET request to directory URL (directory is the base directory for acme) should return the list of URLs for all functions and related information.

#### Basic entities:

- account (user's basic information)
  - status
  - contact (contact information)
  - termsOfServiceAgreed
  - orders (link to orders (request for certificates), followings is the flated information)
    - link1 to order
    - link2 to order
      - status
      - identifiers
      - notBefore
      - notAfter
      - authorization (array of way of authorizations)
        - authz1
        - auth2
          - status
          - expires
          - identifier
          - challenge
          - wildcard
      - finalize
      - certificate

For entities with field **status** (e.g. account, order), there exists a small state machine for transitions of states.

#### Pre-authorization

ACME server must support newAuthz. (Personally thinking, I thought the ACME server might record that the client owns certain domains before but not create certificate yet, once the client is ready, he may then issue the certificate using newAuthz).

#### HTTP challenge

1. The server posts the challenge on the link
2. The client set up a resource link `http://{domain}/.well-known/acme-challenge/{token}`
3. client put the authorization key `token || '.' || base64url(Thumbprint(accountKey))`
4. send POST-as-GET request to inform the server

#### DNS Challenge

1. The server posts the challenge on the link
2. The client fetches the link and retrieves the token
3. The client construct the domain name `_acme-challenge.{domain}` and return the TXT with the digest of authorization key

#### Possible attacks

1. Website delegate certain operations to others. If the web source creating is delegated to attackers, then the attackers can create files related to acme challenge to pass the validation.
2. Redirection may cause the acme validatoin http request forwarded to attacker's server.
3. Malicious DNS may redirect acme servers' request to attackers' server. But it can be mitigated with the followings:
  o  Always querying the DNS using a DNSSEC-validating resolver
    (enhancing security for zones that are DNSSEC-enabled)
  o  Querying the DNS from multiple vantage points to address local
    attackers
  o  Applying mitigations against DNS off-path attackers, e.g., adding
    entropy to requests [DNS0x20] or only using TCP
4. Limit the rate for operations (validation, account registrations, etc.) to prevent DDoS
5. ACME server should always visit the public links during validation to avoid leaking internal information by Server-side request forgery (SSRF).
6. CA should make sure the generated URLs do not show correlations between links and account. One proper example is:

   o  Accounts: https://example.com/acct/:accountID

   o  Orders: https://example.com/order/:orderID

   o  Authorizations: https://example.com/authz/:authorizationID

   o  Certificates: https://example.com/cert/:certID

### MISC

useful linkes:
[PEM and likewise terminology definition](https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file)

ASN.1: Abstract Syntax Notation One is a standard interface description language for defining data structure that can be serialized and deserialized in a cross-platform way.

BER: The format for Basic Encoding Rules specifies a self-describing and self-delimiting format for encoding ASN.1 data structures.

XML: Extensible Markup Language is a markup language and file format for storing. transmitting, and reconstructing arbitrary data.

## IPFS

InterPlantery File System (or IPFS) is a peer-to-perr storage network.

### content addressing

Every piece of the content that uses the IPFS protocal has a content identifier, or CID, that is its hash. 

Interplantery Linked Data (IPLD) translates between hash-linked data structures, allowing for the unification of the data across distributed systems.

### Directed acyclic graphs (DAGs)

IPFS use Merkle DAG to organize the file system. Different parts of the merkle DAGs might refer to the same data which makes it more efficient when doing the database transferring versions.

### Distributed hash tables (DHTs)

DHT is a hash-key to value database and its distributed across all peers. When you need to look up some part of hash table, you may need to ask peers for them.

discovery: find out who owns the item
  |
routing: find out the location of the owners
  |
exchange: connect to the content and get it

### how IPFS is applied in Ethereum

First create an account in IPFS and store related data, then publish the links of related data into the smart contract.

## Blockchain oracle

[reference link](https://ethereum.org/en/developers/docs/oracles/)

Oracles act as a “bridge” connecting smart contracts on blockchains to off-chain data providers.

an oracle is typically made up of a smart contract running on-chain and some off-chain components. The on-chain contract receives requests for data from other smart contracts, which it passes to the off-chain component (called an oracle node). This oracle node can query data sources—using application programming interfaces (APIs), for example—and send transactions to store the requested data in the smart contract's storage.

### Oracle problem

Correctness: An oracle should not cause smart contracts to trigger state changes based on invalid off-chain data. For this reason, an oracle must guarantee authenticity and integrity of data—authenticity means the data was gotten from the correct source, while integrity means the data remained intact (i.e., it wasn’t altered) before being sent on-chain.

Availability: An oracle should not delay or prevent smart contracts from executing actions and triggering state changes. This quality requires that data from an oracle be available on request without interruption.

Incentive compatibility: An oracle should incentivize off-chain data providers to submit correct information to smart contracts. Incentive compatibility involves attributability and accountability. Attributability allows for correlating a piece of external information to its provider, while accountability bonds data providers to the information they give, such that they can be rewarded or penalized based on the quality of information provided.

### Oracle design patterns

1. immediate-read

2. publish-subscribe
  The client needs to poll the server (smart contract) frequently to make sure fetching the most recent result.

3. request-response
  The client sends requests to the server. The server then checks the request and responses correspondingly. 
  Users initiating data queries must cover the cost of retrieving information from the off-chain source. The client contract must also provide funds to cover gas costs incurred by the oracle contract in returning the response via the callback function specified in the request. This will avoid DDoS.

### Types of Oracles

1. Centralized oracles
  Efficient but come with various problems:

   1. Low corresctness guarantees
   2. poor availability
   3. Poor incentive compatibility

2. Decentralized oracles
   Compromise multiple peer-to-perr network that form consensus on off-chain data before sending it to a smart chontract.

   1. High correctness guarantees
   2. Authenticity proofs 
      e.g. TLS, TEE
   3. Consensus-based validation of information
      1. Voting/staking on accuracy of data
         Take the majority of the voting result. And will penalized nodes with deviated result.
      2. Schelling point:
         1. schelling coin
            Each node send answers to a *scalar* question (whose answers are described by magnitude). Nodes with answers within 25th and 75th percentile will be awarded while the rest get penalized.
         2. Maker protocol's oracle
            Nodes in an off-chain P2P network submit market prices for collateral assets and an on-chain oracle will calculate the median of all provided value.
         3. Chainlink Off-Chain Reporting and Witnet
            In both systems, responses from oracle nodes in the peer-to-peer network are aggregated into a single aggregate value, such as a mean or median. Nodes are rewarded or punished according to the extent to which their responses align with or deviate from the aggregate value.
      3. Availability
      4. Good incentive compatibility

### Applications oracles in smart contracts

1. Generate verifiable randomness
   Chainlinks VRF
2. Get outcomes for events
3. Automation smart contracts
   Chainlinks Keeper Networdk

## TLS

### TLS vs SSL

Secure Sockets Layers (SSL) and Transport Layer Security (TLS) are both protocols that aims to secure the internet connections using cryptography. SSL is currently deprecated and TLS (specificially 1.3) is commonly used.
Early version of TLS was developed from SSL, but in later they gradually differed a lot.

### HTTPS

HTTPS is an implementation of TLS encryption on top of the HTTP protocol, which is used by all websites as well as some other web services.

### TLS MISC

[cloudflare TLS introduction](https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/)
[cloudflare TLS handshake](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)

1. Server must install a TLS/SSL certificate which contains:

- who owns the domain
- server's public key

2. Things happened in TLS handshake

- Specify which version of TLS (TLS 1.0, 1.2, 1.3, etc.) they will use
- Decide on which cipher suites (see below) they will use
- Authenticate the identity of the server using the server's TLS certificate
- Generate session keys for encrypting messages between them after the handshake is complete

3. When TLS handshake happens

After TCP connection is finished.

In the server hello, the server will send its certificate to client. The client will then do the authetication with the CA.

## Certificate

[certificate wiki](https://en.wikipedia.org/wiki/X.509)

In cryptography, X.509 is an International Telecommunication Union (ITU) standard defining the format of public key certificates.

