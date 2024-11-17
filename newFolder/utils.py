import matplotlib.pyplot as plt

# Plot training progress
def plot_losses(d_losses, g_losses):
    plt.figure(figsize=(10,5))
    plt.plot(d_losses, label='Discriminator Loss', alpha=0.8)
    plt.plot(g_losses, label='Generator Loss', alpha=0.8)
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.title('GAN Training Progress')
    plt.legend()
    plt.grid(True)
    plt.show()

# Modify learning rate
config['lr'] = 0.0001  # Reduce learning rate

# Add gradient clipping
torch.nn.utils.clip_grad_norm_(generator.parameters(), max_norm=1.0)
torch.nn.utils.clip_grad_norm_(discriminator.parameters(), max_norm=1.0)

# Update optimizers
g_optimizer = Adam(generator.parameters(), lr=config['lr'], betas=(0.5, 0.999))
d_optimizer = Adam(discriminator.parameters(), lr=config['lr'], betas=(0.5, 0.999))