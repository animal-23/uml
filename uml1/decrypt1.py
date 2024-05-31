import base64


def inverse_round_function(data, sub_key):
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



def decrypt(ciphertext, master_key, sub_keys):

    plaintext = ciphertext
    
    # Reverse the order of sub-keys for decryption

    sub_keys = sub_keys[::-1]

    block_size = 16  # Assuming 128-bit block size
    decrypted_data = b''
    for block_start in range(0, len(plaintext), block_size):
        block = plaintext[block_start: block_start + block_size]

        #reversing XOR ciphertext with master key
        block = bytes([a ^ b for a, b in zip(block, master_key)])

        # Split the block into two halves
        left, right = block[:8], block[8:]

        # 8 Rounds of decryption
        for i in range(8):
            
            # Feistel-like structure (reverse)
            round_function_output = inverse_round_function(left, sub_keys[i]) # Apply inverse round function
            temp = round_function_output  # Store the output temporarily
            temp = bytes([a ^ b for a, b in zip(right, temp)]) # Byte-wise XOR
            right, left = left, temp  # Swap halves
            
        # Combine halves and append to decrypted data
        decrypted_data += left + right

    # Remove padding
    padding_length = decrypted_data[-1]
    padding_bytes = decrypted_data[-padding_length:]
    if not (1 <= padding_length <= block_size and all(b == padding_length for b in padding_bytes)):
        print("hi")
        #raise ValueError("Invalid padding")
    decrypted_data = decrypted_data[:-padding_length]

    return decrypted_data.decode("utf-8")  # Decode bytes to string (specify UTF-8)



def main():
    """
    Prompts the user for input data and key filename, encrypts the data, and saves the ciphertext.
    """
    ciphertext_filename = input("Enter the ciphertext filename: ")
    key_filename = input("Enter the key filename: ")


    # Read ciphertext from file
    with open(ciphertext_filename, "r") as f:
        base64_ciphertext = f.read().strip()
    ciphertext = base64.b64decode(base64_ciphertext)  # Decode Base64

    # Import sub-keys and master key from the key file
    with open(key_filename, "r") as f:
        lines = f.readlines()
        master_key = bytes.fromhex(lines[0].strip().split(": ")[1])
        sub_keys = [bytes.fromhex(line.strip().split(": ")[1]) for line in lines[1:]]

    decrypted_data = decrypt(ciphertext, master_key, sub_keys)
    print("Decrypted data:", decrypted_data)

if __name__ == "__main__":
    main()
