from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def pad(data):
    """Dodaje padding tako da podaci budu deljivi sa AES blok veličinom (16 bajtova)."""
    padding_length = 16 - len(data) % 16
    return data + chr(padding_length) * padding_length

def unpad(data):
    """Uklanja padding iz podataka."""
    padding_length = ord(data[-1])
    return data[:-padding_length]

def encrypt_aes(key, plaintext):
    """
    Šifrovanje podataka koristeći AES algoritam u CBC modu.
    :param key: 16, 24 ili 32 bajta (AES ključ)
    :param plaintext: Tekst za šifrovanje
    :return: Šifrovani tekst u Base64 formatu i IV (Base64)
    """
    iv = get_random_bytes(16)  # Inicijalizacioni vektor
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext)
    encrypted_data = cipher.encrypt(padded_data.encode())
    return b64encode(iv).decode(), b64encode(encrypted_data).decode()

def decrypt_aes(key, iv_base64, encrypted_base64):
    """
    Dešifrovanje AES šifrovanog teksta koristeći CBC mod.
    :param key: 16, 24 ili 32 bajta (AES ključ)
    :param iv_base64: IV u Base64 formatu
    :param encrypted_base64: Šifrovani tekst u Base64 formatu
    :return: Originalni (dešifrovani) tekst
    """
    iv = b64decode(iv_base64)
    encrypted_data = b64decode(encrypted_base64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    return unpad(decrypted_data)

if __name__ == "__main__":
    # Generisanje 16-bajtnog ključa
    key = get_random_bytes(16)
    print(f"AES Ključ (Base64): {b64encode(key).decode()}")

    # Unos teksta za šifrovanje
    plaintext = input("Unesi tekst za šifrovanje: ")

    # Šifrovanje
    iv, encrypted_text = encrypt_aes(key, plaintext)
    print(f"\nInicijalizacioni vektor (IV): {iv}")
    print(f"Šifrovani tekst: {encrypted_text}")

    # Dešifrovanje
    decrypted_text = decrypt_aes(key, iv, encrypted_text)
    print(f"Dešifrovani tekst: {decrypted_text}")
