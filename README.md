# SFC
Secure and Forensic Container format - A container format for storing and archiving files.

SFC is a container format which is designed based on the following use cases:
 * Archiving: store data securely for a long time (tens of years)
 * Backup: backup data
 * Forensic file containers: pack files into containers including forensic information (where did the data come from? how has the file been processed?)

Based on the use cases the following requirements are extracted:
 * Data encryption - Files and meta information should (optionally) be encrypted. To provide a high level of data security, asymmetric (or symmetric-asymmetric) encryption should be supported. For example, a backup server which encrypts the data does not need to store the encryption key if asymmetric encryption is used thus being less vulnerable to attacks.
 * Compression - Files should be able to be compressed to save storage space.
 * Data identification - The hashes of the (unencrypted) source files have to be stored to enable file identification. This can be used for incremental backups or forensic applications like NSRL list filtering.
 * Data verification - The hashes of the (optionally encrypted) files in the container have to be stores to enable file verification.
 * Meta data - The container has to provide a system for storing meta data for files, like mac-times, file ownerships, ... This system has to be extensible (not hard-coded) to support future meta data. Additionally, the meta data should be (optionally) be encrypted. Also, global meta data for forensic information (forensic source image, case information, ...) should be stored as well.
 * EDC/ECC - The container format should be able to provide infrastructure for additional error-detecting and -correcting codes to ensure data integrity.

# Basic design

The basic design of SFC is a combination of:
 * An SQLite database which stores meta information of the files in the container
 * A container file (like tar)

The SQLite database as well as the files are stored in the container file. The information which is included in the SQLite database references other files in the container file.
 
# Concepts

## Files

A file is the central entity of the the container.

A file is stored in the container file, optionally compressed and optionally encrypted. The file is compressed first and then encrypted (encrypted files are usually not good compress-able). For each file, the hash of the source is stored in the database. If the file is encrypted, the source hashes are encrypted as well. The hashes of the encrypted file are also stored for file verification.

Optionally, there is support for error-detecting/-correcting data for detecting and possibly correcting file data in-consistences.

## File occurrences/instances

## Encryption and Keys

Encryption of data (files and meta-data) is a key aspect in the container format. For security reasons, asymmetric encryption is preferred: The encryption instance does not need to know the private key for decryption. However, there are technical issues when encrypting large data with asymmetric methods: asymmetric encryption needs more performance and some asymmetric algorithms (like RSA) are not able to encrypt data larger than the key size.

Therefore, it is common practise, to use a symmetric encryption for large data. At first, a symmetric key S is randomly generated and the data D is encrypted (using symmetrical encryption algorithms) using this randomly generated symmetric key: S(D). Afterwards, the (randomly generated) symmetric key S is encrypted with the public key PuA of the asymmetric encryption PuA(S) and deleted. The output of the process is the encrypted data (with the symmetric key) S(A) as well as the encrypted symmetric key (with the asymmetric public key): PuA(S). To decrypt the data, one has to use the private key PrA (private key for public key PuA) to obtain the (unencrypted) symmetric key S = PrA(PuA(S)). With this symmetric key, the encrypted data can be decrypted. This will be called symmetric-asymmetric encryption.

Therefore, SFC knows the following keys:
 * Asymmetric key pairs (public and private key)
 * (Encrypted) symmetric keys

SFC is required to store the following key data:
 * The public key of an asymmetric key pair - The public key is required to add more information (files, meta-data) to the container.
 * The encrypted symmetric key - This key is required to decrypt data which has been encrypted using symmetric-asymmetric encryption. An encrypted symmetric key also requires a reference to the public key which which it is encrypted (the referenced public key has to be stored in the container as well).
 
## Meta data

## Serialization

-> base64 encoding

## Encrypted hash mapping

Needed for fast file identification.

## ES-Hashes

Hashes are important tools for file identification and verification, especially in forensic applications. Hashes are binary values which are usually represented using a hexadecimal digits. Theoretically, every (same-sized) value represents a hash for a valid file. For example, an MD5 hash has a size of 128 bit, so every 128 bit value (theoretically) represents an MD5 hash for valid file. If, for some reason, one or more bits within a hash flip, the error cannot be detected or even corrected. 

Therefore, SFC introduces error-stable Hashes (in short ES-hashes) by using error-correcting codes (likely reed-solomon or similar). So, instead of MD5, ES-MD5 is used and so on. The representation is in the form of md5_in_hex-ecc_data.

Note: This concept should intuatively be called ECC-Hashes (due to the use of error-correcting codes), however the term ECC-Hash is used in the community for Eliptic Curve Cryptography. 

# Data Models/Database Layout

Key
 * id: Integer, primary key
 * key_type: enum(0: asymmetric_public, 1: encrypted_symmetric)
 * parent_key_id: Integer, null-able
 * key: String (for asymmetric_public: the public key in PEM format, for encrypted_symmetric: the encrypted symmetric key, base64 encoded)
 
File
 * id: Integer, primary key
 * key_id: Integer, references(Key.id), null-able
 * compression: String, null-able
 * edc_ecc_method: String, null-able (the error-detecing/-correcting code method)
 * edc_ecc_data: Stirng, null-able (path to the edc/ecc data stored in the container file)
 * hash_sha256_encrypted: String, null-able
 * hash_md5_source: String # if key_id is not null -> encrypted (with key_id) md5 hash of source file, base64 encoded; if key_id is null -> md5 hash of source file
 * hash_sha1_source: String # if key_id is not null -> encrypted (with key_id) sha1 hash of source file, base64 encoded; if key_id is null -> md5 hash of source file
 * hash_sha256_source: String # if key_id is not null -> encrypted (with key_id) sha256 hash of source file, base64 encoded; if key_id is null -> md5 hash of source file

FileInstance
 * id: integer, primary key
 * file_id: Integer, references(File.id)
 
MetaData
 * id: Integer, primary key
 * object_type: Enum(0: global, 1: file, 2: FileInstance)
 * object_id: Integer, null-able, references(File.id or FileInstance.id)
 * key_id: Integer, references(Key.id), null-able
 * name: String
 * value: String
 
EncryptedHash
 * encrypted_hash: string, primary_key
 * file_id: Integer, references(File.id)
 
# Reference implementation

The reference implementation is written in python3.

Used libraries/tools:
 * SQLAlchemy
 * cryptography
 
The first implementation of SFC aims to implement the following features:
 * tar file container
 * SQLite database
 * asymmetric file and meta data encryption using RSA
 * symmetric file and meta data encryption using AES
 * ES-Hashes
 * create a new SFC
 * add files/meta-data to a SFC
 * read/extract files/meta-data from a SFC
 * remove files/meta-data from a SFC
 
The following features will be reserved for later usage:
 * Error-detecting/-correcting codes for file data
