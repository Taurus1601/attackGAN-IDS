import pandas as pd
from datetime import datetime

# Path to the GAN output file
gan_output_path = 'decoded_syscalls.csv'  # Replace with actual path

# Path to the synthetic log file that OSSEC will monitor
log_file_path = "pythonScript/test_syslog.log"  # Replace with actual path

# Load the GAN model output
gan_data = pd.read_csv(gan_output_path)

# Function to create a formatted syslog entry
def generate_syslog_entry(syscall):
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    log_entry = f"{timestamp} myhost kernel: [SYSLOG_GENERATOR] {syscall} syscall executed"
    return log_entry

# Open the log file in append mode
with open(log_file_path, "a") as log_file:
    # Iterate over each row in the GAN output file
    for index, row in gan_data.iterrows():
        # Each row represents a sequence of syscalls (e.g., ["read", "write", "execve"])
        syscall_sequence = row.dropna().tolist()  # Drop NaN values, in case of empty cells
        for syscall in syscall_sequence:
            log_entry = generate_syslog_entry(syscall)
            log_file.write(log_entry + "\n")

print("Synthetic syslog entries generated from model output.")