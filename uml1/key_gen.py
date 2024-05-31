import os
import hashlib
import time

def kdf_stretch(password, salt, iterations, dk_len):
  """
  Derives a key using PBKDF2 with key stretching.
  """
  return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=dk_len)

def generate_sub_keys(key):
  """
  Generates 5 sub-keys of 128 bits each using Feistel and SPN operations.
  """
  sub_keys = []
  for i in range(8):
    # Feistel-like operation: XOR with round constant and rotate
    round_constant = hashlib.sha256(str(i).encode()).digest()[:16]
    temp_key = bytes([b ^ c for b, c in zip(key, round_constant)])  # XOR byte-wise
    temp_key = temp_key[8:] + temp_key[:8]  # Rotate left by 8 bits

    # SPN-like operation: Substitute bytes using a simple S-box
    s_box = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]  
    # Replace with a cryptographically secure S-box generation method
    temp_key = bytes([s_box[b % 16] for b in temp_key])

    sub_keys.append(temp_key)

  return sub_keys

def save_keys_to_file(master_key, sub_keys):
  """
  Saves master key and sub-keys to a text file with a unique name. 
  """
  timestamp = str(int(time.time()))  # Get current timestamp for unique filename
  filename = f"keys_{timestamp}.txt"  # Create filename with timestamp
  with open(filename, "w") as f:
    f.write(f"Master Key: {master_key.hex()}\n")
    for i, sub_key in enumerate(sub_keys):
      f.write(f"Sub-key {i+1}: {sub_key.hex()}\n")
  print(f"Keys saved to: {filename}")

# Example usage
password = "strong_password"  # Replace with user input
salt = os.urandom(16)  # Generate a random salt
iterations = 100000  # Adjust for desired level of key stretching

key = kdf_stretch(password, salt, iterations, 16)  # Generate 128-bit key
sub_keys = generate_sub_keys(key)

print("Master Key:", key.hex())
print("Sub-keys:")
for i, sub_key in enumerate(sub_keys):
  print(f"  Sub-key {i+1}: {sub_key.hex()}")

save_keys_to_file(key, sub_keys)  # Save keys to a unique file
