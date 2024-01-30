import os
import argparse
import struct

KEY = os.urandom(4)

def xor_encrypt_decrypt(data, key):
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    
    return bytes(encrypted_data)

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse()
    
    data = open(args.file, 'rb').read()
    
    ciphertext = xor_encrypt_decrypt(data, KEY)
    
    payload = 0xBAADF00D.to_bytes(4,'little')
    payload += 0xBAADF00D.to_bytes(4, 'little')
    payload += KEY
    payload += len(ciphertext).to_bytes(8, 'little')
    payload += ciphertext
    
    print('[+] payload size: {}'.format(len(payload)))
    print('[+] key: {}'.format(KEY.hex().upper()))
    
    open('rsrcL04d3r/secrets1.bin', 'wb').write(payload)
