# Import required libraries
import numpy as np
import pandas as pd
import torch
from ast import literal_eval
from tqdm import tqdm

# Create first cell for data loading
def load_and_preprocess_data(file_path):
    # Load data
    print("Loading data...")
    data = pd.read_csv(file_path)
    
    # Convert sequences
    print("Converting sequences...")
    data['sequence'] = data['sequence'].apply(literal_eval)
    
    # Get max length
    max_len = max(len(seq) for seq in data['sequence'])
    
    # Pad sequences
    print("Padding sequences...")
    def pad_sequence(seq):
        return np.pad([int(x) for x in seq], 
                     (0, max_len - len(seq)), 
                     'constant')
    
    X = np.array([pad_sequence(seq) for seq in tqdm(data['sequence'])])
    
    # Convert labels
    y = pd.get_dummies(data['label']).values
    
    # Normalize to [0,1]
    X = (X - X.min()) / (X.max() - X.min())
    
    # Convert to tensors
    X_tensor = torch.FloatTensor(X).unsqueeze(1)
    y_tensor = torch.FloatTensor(y)
    
    return X_tensor, y_tensor

# Test the function
X_tensor, y_tensor = load_and_preprocess_data('adfa_ld_processed.csv')
print(f"\nData loaded successfully!")
print(f"X shape: {X_tensor.shape}")
print(f"y shape: {y_tensor.shape}")
print(f"X range: [{X_tensor.min():.2f}, {X_tensor.max():.2f}]")