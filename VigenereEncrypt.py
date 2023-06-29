import string


def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += encrypted_char
            key_index += 1
        else:
            ciphertext += char
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext += decrypted_char
            key_index += 1
        else:
            plaintext += char
    return plaintext


def validate_input(text):
    if not all(char.isalpha() or char.isspace() for char in text):
        raise ValueError("Invalid input! The text should only contain letters and spaces.")


def get_valid_keyword():
    while True:
        keyword = input("Enter the keyword (letters only): ")
        if all(char.isalpha() for char in keyword):
            return keyword
        print("Invalid keyword! Please enter letters only.")


def get_valid_message():
    while True:
        message = input("Enter the message: ")
        try:
            validate_input(message)
            return message
        except ValueError as e:
            print(str(e))


def get_valid_choice():
    while True:
        choice = input("Enter 'E' to encrypt or 'D' to decrypt: ")
        if choice.upper() == 'E' or choice.upper() == 'D':
            return choice.upper()
        print("Invalid choice! Please enter 'E' or 'D'.")


def main():
    print("Vigenère Cipher Program")

    keyword = get_valid_keyword()
    choice = get_valid_choice()
    message = get_valid_message()

    if choice == 'E':
        encrypted_message = vigenere_encrypt(message, keyword)
        print("Encrypted message:", encrypted_message)
    else:
        decrypted_message = vigenere_decrypt(message, keyword)
        print("Decrypted message:", decrypted_message)


if __name__ == '__main__':
    main()
