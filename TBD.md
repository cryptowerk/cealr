##Cleanup Security
###Test in Windows
###Implement file permissions to read only for User non for Group/Others

#SmartStamps
##SMARTSTAMP FORMAT

Evaluate current SmartStamps validate files without Cryptowerk Servers (only SmartStamps)

###Generating+Storing Private Keys
###Extractand export public Keys (including API for publishing public Key)
###Signing
###Creating new Ceal
###Verification of signature
###Verification of new Ceal



#SmartStamps / CryptowerkSeal

OriginProof: OpenPGP

The CW-Seal stage 1 needs to contain

* hash of the document
* the originator
* signature method (simple, openPGP, ….)
* either some packaged data that state the origin (simple Electronic signeture like an image of a written signature) or
* the signature of the document with the originators private key
* originator’s public key or reference (e.g. download URI) to the originator’s public key

Signature:
* currently signing with OpenPGP on local hardware (e.g. originators laptop/cell phone) with the private key of the originator which is stored on the local hardware. However. Other asymmetric signature standards have similar components.
* The public key can be extracted from the private key and must be available for the verification of the document. Therefore it may be:
  * either part of the meta data of the smart stamp (possible vulnerabilities)
  * or referenced in the metadata (URL where to download) after uploaded to a public key server (e.g. https://pgp.mit.edu/)
  * or by default stored either in a public blockchain or in Crypto Cloud. Since Crypto Cloud is in our control this option would make it possible to monetize verification of SmartStamps (since this process currently would not touch our API. In this case a reference to the PublicKey must either be stored in the document's meta data or standardized (e.g. retrievable by originator from Crypto Cloud).
* since The signature needs to be revocable (in order to count as advanced) We need an API to revoke stored signatures (without deleting them, documents until revocation could stay valid, since we can prof that they existed before revocation)

The CWSeal stage 1 is sent to the Cryptowerk API and there processed as follows:
* Added timestamp when we received it
* extract the Public Key, store it (if we not already have it stored) and replace it with a reference to where we stored it.
* Hash over all these data to be added as meta data hash
* Add the SmartSamps for both hashes the document hash and the meta data hash (Used hardware and Services are AWS and the used Blockchain)

This enriched CWSeal is the final result that contains prof of existence and origin.
