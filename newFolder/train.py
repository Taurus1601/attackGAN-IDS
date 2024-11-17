# train.py
from models import Generator, Discriminator
import torch
from torch.optim import Adam
import os
from data_loader import *
from datetime import datetime
from tqdm.auto import tqdm  # Changed to tqdm.auto


# Create folder for model checkpoints
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
save_dir = f'model_checkpoints_{timestamp}'
os.makedirs(save_dir, exist_ok=True)

# Configuration dictionary
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

# Initialize models
sequence_length = X_tensor.shape[2]  # From your data preprocessing
generator = Generator(config['latent_dim'], sequence_length).to(config['device'])
discriminator = Discriminator(sequence_length).to(config['device'])


def train_gan():
    # Initialize loss lists
    d_losses = []
    g_losses = []
    
    for epoch in range(config['n_epochs']):
        d_epoch_loss = 0
        g_epoch_loss = 0
        
        # Modified progress bar
        for batch_idx, (real_data, _) in enumerate(train_loader):
            if batch_idx % 10 == 0:
                print(f'Epoch [{epoch+1}/{config["n_epochs"]}] Batch [{batch_idx}/{len(train_loader)}]', end='\r')
                
            batch_size = real_data.size(0)
            real_data = real_data.to(config['device'])

            # Ground truths
            valid = torch.ones(batch_size, 1).to(config['device'])
            fake = torch.zeros(batch_size, 1).to(config['device'])

            # Train Generator
            g_optimizer.zero_grad()
            z = torch.randn(batch_size, config['latent_dim']).to(config['device'])
            generated_data = generator(z)
            g_loss = adversarial_loss(discriminator(generated_data), valid)
            g_loss.backward()
            g_optimizer.step()

            # Train Discriminator
            d_optimizer.zero_grad()
            real_loss = adversarial_loss(discriminator(real_data), valid)
            fake_loss = adversarial_loss(discriminator(generated_data.detach()), fake)
            d_loss = (real_loss + fake_loss) / 2
            d_loss.backward()
            d_optimizer.step()

            # Update losses
            d_epoch_loss += d_loss.item()
            g_epoch_loss += g_loss.item()

        # Print epoch results
        print(f'\nEpoch [{epoch+1}/{config["n_epochs"]}] D_loss: {d_epoch_loss/len(train_loader):.4f} G_loss: {g_epoch_loss/len(train_loader):.4f}')

        # Save epoch losses
        d_losses.append(d_epoch_loss/len(train_loader))
        g_losses.append(g_epoch_loss/len(train_loader))
        
        # Save model checkpoint every 1000 epochs
        if (epoch + 1) % 1000 == 0:
            checkpoint_path = os.path.join(save_dir, f'checkpoint_epoch_{epoch+1}.pt')
            torch.save({
                'epoch': epoch,
                'generator_state_dict': generator.state_dict(),
                'discriminator_state_dict': discriminator.state_dict(),
                'g_optimizer_state_dict': g_optimizer.state_dict(),
                'd_optimizer_state_dict': d_optimizer.state_dict(),
                'g_loss': g_epoch_loss/len(train_loader),
                'd_loss': d_epoch_loss/len(train_loader)
            }, checkpoint_path)
            print(f"Checkpoint saved: {checkpoint_path}")
    
    return d_losses, g_losses

# Start training
d_losses, g_losses = train_gan()