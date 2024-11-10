import pandas as pd
import json

# Load the denormalized data (GAN output) in integer format
gan_output_path = 'denormalized_data_integers.csv'
gan_data = pd.read_csv(gan_output_path, header=None)  # No headers in the CSV, load as raw data

# Load the mapping dictionary from JSON file
mapping_path = 'syscall_dict.json'
with open(mapping_path, 'r') as f:
    syscall_dict = json.load(f)

# Function to decode a sequence of integers using the dictionary
def decode_syscall_sequence(sequence, syscall_dict):
    return [syscall_dict.get(str(int_val), "Unknown") for int_val in sequence]

# Process each row in the CSV
decoded_sequences = []
for index, row in gan_data.iterrows():
    # Convert the row to a list of integers
    sequence = row.tolist()  # Treats each row as a sequence of integers
    decoded_sequence = decode_syscall_sequence(sequence, syscall_dict)
    decoded_sequences.append(decoded_sequence)

# Convert to DataFrame and save the result
decoded_df = pd.DataFrame(decoded_sequences)
decoded_df.to_csv("decoded_syscalls.csv", index=False)

print("Decoded system calls have been saved to 'decoded_syscalls.csv'.")