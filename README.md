# EHN 410 - Group 7

## Group members

* Mohamed Ameen Omar (u16055323)
* Douglas Healy (u16018100)
* Llewellyn Moyse (u15100708)

***

## RSA Key Generation

1. Open a Linux Terminal.
2. Navigate to the root directory containing the *rsakeygen* source code.
3. Run the *"make rsakeygen"* command.
4. An executable called *rsakeygen* will be created.
5. Use *"./rsakeygen"* to run the RSA Key Generation program (if no input parameters are specified, a help menu will be displayed)
6. A list of input parameters and respective default values can be seen below:

| Parameter |                                    Description                                   | Default Value |
|:---------:|:--------------------------------------------------------------------------------:|:-------------:|
| -h        | Prints out the help menu                                                         |               |
| -b        | Specifies the number of bits for the public/private keys to be generated         | None          |
| -KU       | Specifies the file to which the **public** key will be written                   | None          |
| -KR       | Specifies the file to which the **private** key will be written                  | None          |
| -key      | Specifies the key for the initialisation of the RNG (in hex by default)          | None          |
| -kf       | Specifies the path to the key for the initialisation of the RNG (hex by default) | None          |
| -ascii    | Specifies that the key used is in ascii instead of hex                           | Hex           |

### RSA Key Generation Usage Example

```console
./rsakeygen -b bits -KU public_key_file -KR private_key_file -key key
```

***

## RSA Encryption

1. Open a Linux Terminal.
2. Navigate to the root directory containing the *rsaencrypt* source code.
3. Run the *"make rsaencrypt"* command.
4. An executable called *rsaencrypt* will be created.
5. Use *"./rsaencrypt"* to run the RSA Encryption program (if no input parameters are specified, a help menu will be displayed)
6. A list of input parameters and respective default values can be seen below:

| Parameter |                       Description                       | Default Value |
|:---------:|:-------------------------------------------------------:|:-------------:|
| -h        | Prints out the help menu                                |               |
| -key      | Specifies the RC4 key to encrypt/decrypt                | None          |
| -fo       | Specifies the file to write the encrypted result to     | None          |
| -KU       | Specifies the RSA public key file to use for encryption | None          |
| -kf       | Specifies the path to the RC4 key to encrypt/decrypt    | None          |
| -hex      | Specifies that the key used is in hex instead of ascii  | ascii         |

### RSA Encryption Usage Example

```console
./rsaencrypt -key key -fo outputfile -KU public_key_file
```

***

## RSA Decryption

1. Open a Linux Terminal.
2. Navigate to the root directory containing the *rsadecrypt* source code.
3. Run the *"make rsadecrypt"* command.
4. An executable called *rsadecrypt* will be created.
5. Use *"./rsadecrypt"* to run the RSA Decryption program (if no input parameters are specified, a help menu will be displayed)
6. A list of input parameters and respective default values can be seen below:

| Parameter |                        Description                       | Default Value |
|:---------:|:--------------------------------------------------------:|:-------------:|
| -h        | Prints out the help menu                                 |               |
| -fi       | Specifies the path to the key to decrypt                 | None          |
| -key      | Specifies the key to decrypt                             | None          |
| -KR       | Specifies the RSA private key file to use for decryption | None          |
| -fo       | Specifies the file to write the decrypted result to      | None          |

### RSA Decryption Usage Example

```console
./rsadecrypt -fi inputfile -KR private_key_file -fo outputfile
```

***

## RC4

1. Open a Linux Terminal.
2. Navigate to the root directory containing the *rc4* source code.
3. Run the *"make rc4"* command.
4. An executable called *rc4* will be created.
5. Use *"./rc4"* to run the RC4 Encryption/Decryption Program (if no input parameters are specified, a help menu will be displayed)
6. A list of input parameters and respective default values can be seen below:

| Parameter |                                          Description                                          | Default Value |
|:---------:|:---------------------------------------------------------------------------------------------:|:-------------:|
| -h        | Prints out the help menu                                                                      |               |
| -fi       | Specifies the file to encrypt/decrypt                                                         | None          |
| -fo       | Specifies the file to write the encrypted/decrypted result to                                 | None          |
| -kf       | Specifies the path to the encryption key for the initialisation of the RNG (ascii by default) | None          |
| -hex      | Specifies that the key used is in hex instead of ascii                                        | ascii         |

>* If no key is specified by the command line parameters then the user will be prompted for a key at runtime.
>* All keys must have a maximum size of 16 bytes.

### RC4 Encryption/Decryption Usage Example

```console
./rc4 -fi inputfile -fo outputfile -kf keyfile
```

***