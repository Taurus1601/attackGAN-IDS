import os
import pandas as pd

# Define paths to your folders
attack_data_path = 'data/a-labelled-version-of-the-ADFA-LD-dataset/ADFA-LD/Attack_Data_Master'
training_data_path = 'data/a-labelled-version-of-the-ADFA-LD-dataset/ADFA-LD/Training_Data_Master'

# Initialize empty lists to store data
attack_data = []
training_data = []

# Load attack data
for subdir, _, files in os.walk(attack_data_path):
    for file in files:
        file_path = os.path.join(subdir, file)
        with open(file_path, 'r') as f:
            syscalls = list(map(int, f.read().split()))  # Convert each syscall to an integer
            attack_data.append({'sequence': syscalls, 'label': 'malicious'})

# Load training (benign) data
for file in os.listdir(training_data_path):
    file_path = os.path.join(training_data_path, file)
    with open(file_path, 'r') as f:
        syscalls = list(map(int, f.read().split()))  # Convert each syscall to an integer
        training_data.append({'sequence': syscalls, 'label': 'benign'})

# Combine and find the maximum syscall value for normalization
all_data = attack_data + training_data
max_value = max(max(seq['sequence']) for seq in all_data)

# Normalize sequences
for data_point in all_data:
    data_point['sequence'] = [x / max_value for x in data_point['sequence']]

# Convert to DataFrame
df = pd.DataFrame(all_data)

# Shuffle data and save to processed data folder
df = df.sample(frac=1).reset_index(drop=True)
df.to_csv('adfa__processed.csv', index=False)
print("Data preprocessing complete. Saved to 'data/processed/adfa_ld_processed.csv'.")
