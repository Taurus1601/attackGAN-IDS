import pandas as pd
import json

# Load the mapping dictionary from JSON file
mapping_path = 'syscall_dict.json'
with open(mapping_path, 'r') as f:
    syscall_dict = json.load(f)

# Function to decode a sequence of integers using the dictionary
def decode_syscall_sequence(sequence, syscall_dict):
    return [syscall_dict.get(str(int_val), "Unknown") for int_val in sequence]

# Load the data from the text file
with open('attack.txt', 'r') as file:
    data = file.read()

# Convert the data to a list of integers
sequence = list(map(int, data.split()))

# Decode the sequence
decoded_sequence = decode_syscall_sequence(sequence, syscall_dict)

# Convert to DataFrame and save the result
decoded_df = pd.DataFrame([decoded_sequence])
decoded_df.to_csv("attack_decode.csv", index=False)

print("Decoded system calls have been saved to 'decoded_uad_adduser.csv'.")