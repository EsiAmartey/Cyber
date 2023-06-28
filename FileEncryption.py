from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from getpass import getpass
import os
import sys
import progressbar


def derive_key(password, salt):
    # Derive a secure key from the password and salt using PBKDF2
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    return key


def encrypt_file(key, file_path):
    # Generate a random initialization vector
    iv = get_random_bytes(AES.block_size)

    # Create the AES cipher object with the key and mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Open the input and output files
    with open(file_path, 'rb') as file:
        plain_text = file.read()

    # Pad the plaintext to be a multiple of the block size
    padded_text = pad_text(plain_text, AES.block_size)

    # Encrypt the padded plaintext
    cipher_text = cipher.encrypt(padded_text)

    # Write the IV and cipher text to the output file
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        file.write(iv)
        file.write(cipher_text)

    print(f'File encrypted successfully: {encrypted_file_path}')


def decrypt_file(key, encrypted_file_path):
    # Open the encrypted file
    with open(encrypted_file_path, 'rb') as file:
        iv = file.read(AES.block_size)
        cipher_text = file.read()

    # Create the AES cipher object with the key, mode, and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the cipher text
    decrypted_text = cipher.decrypt(cipher_text)

    # Remove the padding from the decrypted text
    plain_text = remove_padding(decrypted_text)

    # Write the decrypted text to the output file
    decrypted_file_path = os.path.splitext(encrypted_file_path)[0]
    with open(decrypted_file_path, 'wb') as file:
        file.write(plain_text)

    print(f'File decrypted successfully: {decrypted_file_path}')


def pad_text(text, block_size):
    padding_size = block_size - (len(text) % block_size)
    padding = bytes([padding_size] * padding_size)
    return text + padding


def remove_padding(text):
    padding_size = text[-1]
    return text[:-padding_size]


def calculate_file_hash(file_path):
    # Calculate the cryptographic hash of the file
    hash_object = SHA256.new()

    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_object.update(chunk)

    return hash_object.hexdigest()


def verify_file_integrity(file_path, original_hash):
    # Verify the integrity of the decrypted file
    current_hash = calculate_file_hash(file_path)

    if current_hash == original_hash:
        print('File integrity verified.')
    else:
        print('WARNING: File integrity check failed! The file may have been tampered with.')


def main():
    print('1. Encrypt a file')
    print('2. Decrypt a file')
    choice = input('Select an option (1 or 2): ')

    if choice == '1':
        file_path = input('Enter the path to the file to encrypt: ')
        password = getpass('Enter the encryption password: ')
        salt = get_random_bytes(16)  # Generate a random salt

        # Derive the encryption key from the password and salt
        key = derive_key(password, salt)

        encrypt_file(key, file_path)

        # Store the salt alongside the encrypted file
        salt_file_path = file_path + '.salt'
        with open(salt_file_path, 'wb') as file:
            file.write(salt)

        print(f'Salt file created: {salt_file_path}')

    elif choice == '2':
        encrypted_file_path = input('Enter the path to the file to decrypt: ')
        password = getpass('Enter the decryption password: ')

        # Load the salt from the salt file
        salt_file_path = encrypted_file_path + '.salt'
        if not os.path.exists(salt_file_path):
            print('Error: Salt file not found.')
            sys.exit(1)

        with open(salt_file_path, 'rb') as file:
            salt = file.read()

        # Derive the decryption key from the password and salt
        key = derive_key(password, salt)

        decrypt_file(key, encrypted_file_path)

        original_hash = input('Enter the original file hash: ')
        verify_file_integrity(decrypted_file_path, original_hash)

    else:
        print('Invalid choice.')


if __name__ == '__main__':
    main()
