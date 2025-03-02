from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import re

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_image(image_path, key):
    with open(image_path, 'rb') as img_file:
        image_data = img_file.read()
    
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(image_data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + encrypted_data

def decrypt_image(encrypted_data, key):
    try:
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return decrypted_data
    except Exception as e:
        print("Error al descifrar la imagen: Clave incorrecta o datos corruptos.")
        return None

action = input("¿Deseas codificar (C) o decodificar (D) una imagen? (C/D): ").strip().lower()
password = input("Introduce la contraseña para la clave AES: ")
key = derive_key(password)

script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "imagen_cifrada.txt")

if action == 'c':
    image_path = input("Introduce la ruta exacta de la imagen a cifrar: ")
    encrypted_data = encrypt_image(image_path, key)
    hex_encrypted_text = encrypted_data.hex()
    
    with open(file_path, 'w') as file:
        file.write(hex_encrypted_text)
    
    print("Texto cifrado guardado en:", file_path)

elif action == 'd':
    if not os.path.exists(file_path):
        print("Error: No se encontró el archivo con el texto cifrado. Primero debes cifrar una imagen.")
    else:
        with open(file_path, 'r') as file:
            hex_encrypted_text = file.read().strip()
        
        if not re.fullmatch(r'[0-9a-fA-F]+', hex_encrypted_text):
            print("Error: El texto ingresado no es un hexadecimal válido.")
        else:
            encrypted_data = bytes.fromhex(hex_encrypted_text)
            decrypted_data = decrypt_image(encrypted_data, key)
            
            if decrypted_data:
                output_path = os.path.join(script_dir, "imagen_descifrada.png")
                with open(output_path, 'wb') as out_file:
                    out_file.write(decrypted_data)
                print("Imagen descifrada guardada en:", output_path)
else:
    print("Opción no válida. Por favor, elige 'C' para codificar o 'D' para decodificar.")