from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os


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


def main():
    key = get_random_bytes(AES.block_size)  # Generate a random encryption key

    print('1. Encrypt a file')
    print('2. Decrypt a file')
    choice = input('Select an option (1 or 2): ')

    if choice == '1':
        file_path = input('Enter the path to the file to encrypt: ')
        encrypt_file(key, file_path)
    elif choice == '2':
        encrypted_file_path = input('Enter the path to the file to decrypt: ')
        decrypt_file(key, encrypted_file_path)
    else:
        print('Invalid choice.')


if __name__ == '__main__':
    main()
