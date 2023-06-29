import string
import random


def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext


def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext


def generate_salt():
    return random.randint(1, 25)


def validate_shift_value(shift):
    if not isinstance(shift, int):
        raise ValueError("Shift value must be an integer.")
    if shift < 1 or shift > 25:
        raise ValueError("Shift value must be between 1 and 25.")


def caesar_encrypt_advanced(plaintext, shift, salt):
    validate_shift_value(shift)
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift + salt) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift + salt) % 26 + ord('A'))
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext


def caesar_decrypt_advanced(ciphertext, shift, salt):
    validate_shift_value(shift)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                decrypted_char = chr((ord(char) - ord('a') - shift - salt) % 26 + ord('a'))
            else:
                decrypted_char = chr((ord(char) - ord('A') - shift - salt) % 26 + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext


def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            if char.islower():
                shift = ord(key[i % key_length].lower()) - ord('a')
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                shift = ord(key[i % key_length].upper()) - ord('A')
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            if char.islower():
                shift = ord(key[i % key_length].lower()) - ord('a')
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                shift = ord(key[i % key_length].upper()) - ord('A')
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext


# Example usage
plain_text = "Hello, World!"
shift_value = 3
salt_value = generate_salt()
encryption_key = "SECRET"

encrypted_text_caesar = caesar_encrypt(plain_text, shift_value)
decrypted_text_caesar = caesar_decrypt(encrypted_text_caesar, shift_value)

encrypted_text_advanced = caesar_encrypt_advanced(plain_text, shift_value, salt_value)
decrypted_text_advanced = caesar_decrypt_advanced(encrypted_text_advanced, shift_value, salt_value)

encrypted_text_vigenere = vigenere_encrypt(plain_text, encryption_key)
decrypted_text_vigenere = vigenere_decrypt(encrypted_text_vigenere, encryption_key)

print("Caesar Encryption:")
print("Plaintext:", plain_text)
print("Encrypted text:", encrypted_text_caesar)
print("Decrypted text:", decrypted_text_caesar)
print()

print("Advanced Caesar Encryption:")
print("Plaintext:", plain_text)
print("Encrypted text:", encrypted_text_advanced)
print("Decrypted text:", decrypted_text_advanced)
print()

print("Vigenère Encryption:")
print("Plaintext:", plain_text)
print("Encrypted text:", encrypted_text_vigenere)
print("Decrypted text:", decrypted_text_vigenere)
