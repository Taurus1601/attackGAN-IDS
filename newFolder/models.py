# models.py
import torch
import torch.nn as nn

# [Paste the ResidualBlock, Generator, and Discriminator classes here]
import torch
import torch.nn as nn

class ResidualBlock(nn.Module):
    def __init__(self, in_features):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(in_features, in_features),
            nn.LayerNorm(in_features),
            nn.LeakyReLU(0.2),
            nn.Linear(in_features, in_features),
            nn.LayerNorm(in_features)
        )
        
    def forward(self, x):
        return x + self.block(x)

class Generator(nn.Module):
    def __init__(self, latent_dim, sequence_length):
        super().__init__()
        
        self.projection = nn.Sequential(
            nn.Linear(latent_dim, 512),
            nn.LayerNorm(512),
            nn.LeakyReLU(0.2)
        )
        
        self.main = nn.Sequential(
            ResidualBlock(512),
            nn.Linear(512, 1024),
            nn.LayerNorm(1024),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            
            ResidualBlock(1024),
            nn.Linear(1024, 2048),
            nn.LayerNorm(2048),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            
            ResidualBlock(2048),
            nn.Linear(2048, sequence_length),
            nn.Sigmoid()
        )
        
        # Weight initialization
        self.apply(self._init_weights)
        
    def _init_weights(self, m):
        if isinstance(m, nn.Linear):
            nn.init.kaiming_normal_(m.weight)
            if m.bias is not None:
                nn.init.constant_(m.bias, 0)
                
    def forward(self, z):
        x = self.projection(z)
        return self.main(x)

class Discriminator(nn.Module):
    def __init__(self, sequence_length):
        super().__init__()
        
        self.main = nn.Sequential(
            nn.Linear(sequence_length, 2048),
            nn.LayerNorm(2048),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            
            ResidualBlock(2048),
            nn.Linear(2048, 1024),
            nn.LayerNorm(1024),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            
            ResidualBlock(1024),
            nn.Linear(1024, 512),
            nn.LayerNorm(512),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            
            ResidualBlock(512),
            nn.Linear(512, 1),
            nn.Sigmoid()
        )
        
        # Weight initialization
        self.apply(self._init_weights)
        
    def _init_weights(self, m):
        if isinstance(m, nn.Linear):
            nn.init.kaiming_normal_(m.weight)
            if m.bias is not None:
                nn.init.constant_(m.bias, 0)
                
    def forward(self, x):
        return self.main(x)

# Updated configuration
config = {
    'n_epochs': 200,
    'batch_size': 64,
    'lr': 0.0001,
    'beta1': 0.5,
    'beta2': 0.999,
    'latent_dim': 128,
    'device': torch.device('cuda' if torch.cuda.is_available() else 'cpu'),
    'gradient_penalty_weight': 10.0,
    'n_critic': 5
}