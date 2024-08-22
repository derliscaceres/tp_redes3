from Crypto.Cipher import DES
import time

def des_encrypt(key, plaintext):
    des = DES.new(key, DES.MODE_ECB)
    return des.encrypt(plaintext)

def des_decrypt(key, ciphertext):
    des = DES.new(key, DES.MODE_ECB)
    return des.decrypt(ciphertext)

def generate_forward_table(plaintext, k1_range):
    print("Generando la tabla para k1...")
    inicio = time.time()
    forward_table = {}
    for k1 in k1_range:
        k1_bytes = k1.to_bytes(8, byteorder='big')
        encrypted_text = des_encrypt(k1_bytes, plaintext)
        forward_table[encrypted_text] = k1
    fin = time.time()
    print("Tabla generada en ", fin - inicio, "segundos.")
    return forward_table

def generate_backward_table(ciphertext, k2_range):
    print("Generando la tabla para k2...")
    inicio = time.time()
    backward_table = {}
    for k2 in k2_range:
        k2_bytes = k2.to_bytes(8, byteorder='big')
        decrypted_text = des_decrypt(k2_bytes, ciphertext)
        backward_table[decrypted_text] = k2
    fin = time.time()
    print("Tabla generada en ", fin - inicio, "segundos.")
    return backward_table

def meet_in_the_middle_attack(plaintext, ciphertext, k1_range, k2_range):
    forward_table = generate_forward_table(plaintext, k1_range)
    backward_table = generate_backward_table(ciphertext, k2_range)
    
    print("Buscando k1 y k2...")
    contador = 0
    for encrypted_text in forward_table:
        contador += 1
        if encrypted_text in backward_table:
            print(f"Coincidencia encontrada en {contador} iteraciones.")
            k1 = forward_table[encrypted_text]
            k2 = backward_table[encrypted_text]
            return k1, k2
    print(f"No se encontraron coincidencias en {contador} iteraciones.")
    return None, None

k1_range = range(0x000000, 0x1000000) 
k2_range = range(0x000000, 0x1000000)

plaintext = bytes.fromhex("ABCDEF0123456789")
ciphertext = bytes.fromhex("160BD461B7BE9BD3")

inicio = time.time()
k1, k2 = meet_in_the_middle_attack(plaintext, ciphertext, k1_range, k2_range)
fin = time.time()

print("Tiempo de ejecución:", fin - inicio, "segundos.")

if k1 is not None and k2 is not None:
    print(f"Claves: K1 = {k1:016x}, K2 = {k2:016x}")
else:
    print("No hubo coincidencia.")
