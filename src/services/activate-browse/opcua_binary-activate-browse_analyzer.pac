## opcua_binary-browse_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the browse service.
##
## Author:  Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {
    #
    # BrowseActivate
    #
import base64

def vigenere_decode(ciphertext: bytes, key: bytes) -> bytes:
    ciphertext = base64.b64decode(ciphertext)
    plaintext = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        plaintext[i] = (ciphertext[i] - ord(key[i % len(key)])) % 256
    return plaintext



def decode_data(key):
    with open(inputFolderPath, "rb") as input:
        encoded_message = input.read()
        
    decrypted_message_bytes = vigenere_decode(encoded_message,key)

    with open(outputFolderPath, "wb") as output:
        output.write(decrypted_message_bytes)

inputFolderPath = ""
outputFolderPath = ""
key = "supersecretkey"
decode_data(key)



};
