import pandas as pd

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'   # Yellow
    FAIL = '\033[91m'      # Red
    ENDC = '\033[0m'       # Reset
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Load the log file
log_path = "auth.log"  # Make sure this path is correct
with open(log_path, "r") as f:
    lines = f.readlines()

# ========== Detect Failed Logins ==========
failed_logins = []
for line in lines:
    if "Invalid user" in line:
        timestamp = line.split()[0]
        ip = line.split()[-1]
        failed_logins.append({"timestamp": timestamp, "ip": ip})

df_failed = pd.DataFrame(failed_logins)

print(f"{bcolors.FAIL}[!] Top Failed Login IPs:{bcolors.ENDC}")
print(f"{bcolors.OKBLUE}[DEBUG] Raw failed login data:{bcolors.ENDC}")
print(df_failed)
if not df_failed.empty:
    print(df_failed['ip'].value_counts().head())

# ========== Unusual IPs ==========
internal_ips = ['127.', '192.168.', '10.', '::1']
unusual_ips = df_failed[~df_failed['ip'].astype(str).str.startswith(tuple(internal_ips))]['ip'].unique().tolist()
print(f"\n{bcolors.WARNING}[!] Unusual IPs detected:{bcolors.ENDC}")
print(unusual_ips)

# ========== Sudo Usage ==========
print(f"\n{bcolors.OKGREEN}[!] Detected sudo commands:{bcolors.ENDC}")
for line in lines:
    if "sudo:" in line and "COMMAND=" in line:
        print(line.strip())

# ========== Lateral Movement ==========
print(f"\n{bcolors.HEADER}[!] Lateral movement attempts (internal IPs):{bcolors.ENDC}")
lateral_moves = []
for line in lines:
    if "sshd" in line and any(ip in line for ip in internal_ips):
        lateral_moves.append(line.strip())
print(lateral_moves)
