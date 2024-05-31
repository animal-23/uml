import os
import time
import base64

def encrypt(data, key_filename):
    """
    Encrypts data using a custom algorithm with 8 rounds and sub-keys from a file.
    """
    block_size = 16  # Assuming 128-bit block size

    # Calculate padding length
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size

    # Pad data to a multiple of block size
    data += bytes([padding_length]) * padding_length

    
    # Import sub-keys from the key file
    sub_keys = import_sub_keys(key_filename)

    ciphertext = b''
    for block_start in range(0, len(data), block_size):
        block = data[block_start: block_start + block_size]

        
        # Split the block into two halves
        left, right = block[:8], block[8:]

        # 8 Rounds of encryption
        for i in range(8):
            
            # Feistel-like structure
            round_function_output = round_function(right, sub_keys[i+1])  # Apply round function
            temp = bytes([a ^ b for a, b in zip(left, round_function_output)])  # Byte-wise XOR
            left, right = right, temp  # Swap halves
    

        before_master_cipher = b''
        before_master_cipher = left + right
        # XOR ciphertext with master key
        master_key = sub_keys[0]
        ciphertext_master = bytes([a ^ b for a, b in zip(before_master_cipher, master_key)])

        # Combine halves and append to ciphertext
        ciphertext += ciphertext_master


    # Extract the timestamp from the key filename
    timestamp = key_filename.split("_")[1].split(".")[0]

    # Generate cipher filename with key timestamp and .txt extension
    cipher_filename = f"ciphertext_{timestamp}.txt"

    

    # Encode ciphertext using Base64
    base64_ciphertext = base64.b64encode(ciphertext).decode()  # Encode and convert to string

    # Save Base64 encoded ciphertext to the text file
    with open(cipher_filename, "w") as f:
        f.write(base64_ciphertext)
        

    print(f"Ciphertext (binary) saved to: {cipher_filename}")
    print("Encrypted data (Base64):", base64_ciphertext)
    return ciphertext

def round_function(data, sub_key):
    """
    Round function with substitution and diffusion.
    """
    # Substitution using the S-box
    
    s_box = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
    temp = bytes([s_box[b % 16] for b in data])    

    # Diffusion using bit rotation and XOR with sub-key
    temp = temp[2:] + temp[:2]  # Rotate left by 2 bits
    temp = bytes([b ^ c for b, c in zip(temp, sub_key[:8])])
    temp = bytes([b ^ c for b, c in zip(temp, sub_key[8:])])
    return temp

def import_sub_keys(filename):
    """
    Imports sub-keys from a text file.
    """
    sub_keys = []
    with open(filename, "r") as f:
        lines = f.readlines()  
        for line in lines:
            key_value = line.strip().split(": ")[1]  # Extract hex key value
            sub_keys.append(bytes.fromhex(key_value))
    return sub_keys

def main():
    """
    Prompts the user for input data and key filename, encrypts the data, and saves the ciphertext.
    """
    

    data_input = input("Enter the data to encrypt: ")
    data = data_input.encode()  # Convert data to bytes

    key_filename = input("Enter the key filename: ")
    ciphertext = encrypt(data, key_filename)


if __name__ == "__main__":
    main()
