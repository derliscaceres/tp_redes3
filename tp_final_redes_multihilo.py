import multiprocessing
from Crypto.Cipher import DES

def des_encrypt(key, plaintext):
    des = DES.new(key, DES.MODE_ECB)
    return des.encrypt(plaintext)

def des_decrypt(key, ciphertext):
    des = DES.new(key, DES.MODE_ECB)
    return des.decrypt(ciphertext)

def generate_forward_table(plaintext, k1_range):
    forward_table = {}
    for k1 in k1_range:
        k1_bytes = k1.to_bytes(8, byteorder='big')
        encrypted_text = des_encrypt(k1_bytes, plaintext)
        forward_table[encrypted_text] = k1
    return forward_table

def generate_backward_table(ciphertext, k2_range):
    backward_table = {}
    for k2 in k2_range:
        k2_bytes = k2.to_bytes(8, byteorder='big')
        decrypted_text = des_decrypt(k2_bytes, ciphertext)
        backward_table[decrypted_text] = k2
    return backward_table

def meet_in_the_middle_worker(plaintext, ciphertext, k1_subrange, k2_range, result_queue):
    forward_table = generate_forward_table(plaintext, k1_subrange)
    backward_table = generate_backward_table(ciphertext, k2_range)
    
    for encrypted_text in forward_table:
        if encrypted_text in backward_table:
            k1 = forward_table[encrypted_text]
            k2 = backward_table[encrypted_text]
            result_queue.put((k1, k2))
            return

def meet_in_the_middle_parallel(plaintext, ciphertext, k1_range, k2_range, num_processes):
    chunk_size = len(k1_range) // num_processes
    result_queue = multiprocessing.Queue()

    processes = []
    for i in range(num_processes):
        k1_subrange = range(k1_range.start + i * chunk_size, k1_range.start + (i + 1) * chunk_size)
        p = multiprocessing.Process(target=meet_in_the_middle_worker, args=(plaintext, ciphertext, k1_subrange, k2_range, result_queue))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    if not result_queue.empty():
        return result_queue.get()
    else:
        return None, None

# Define los rangos de clave
k1_range = range(0x000000, 0x1000000)
k2_range = range(0x000000, 0x1000000)

# Texto plano y cifrado
plaintext = bytes.fromhex("ABCDEF0123456789")
ciphertext = bytes.fromhex("160BD461B7BE9BD3")

# Ejecutar el ataque con 4 procesos en paralelo
k1, k2 = meet_in_the_middle_parallel(plaintext, ciphertext, k1_range, k2_range, num_processes=4)

if k1 is not None and k2 is not None:
    print(f"Claves encontradas: K1 = {k1:014x}, K2 = {k2:014x}")
else:
    print("No se encontraron claves.")
