## Installation

1. Clone the repository:
```bash
git clone https://github.com/captainfaisal/PPPoE-Attack.git
cd PPPoE-Attack
```

## Usage

### Basic Operation
After running the code, connect to the router through ethernet to get PPPoE credentials.
```bash
sudo python3 attack.py
```
For specific interface other than eth0, run

```bash
sudo python3 attack.py -i <your-interface>
```
To get detailed output run the code with -v.

### Example Output
```
[+] PPPoE Server running on eth0 (MAC: xx:xx:xx:xx:xx:xx)
[+] Waiting for PPPoE clients...

[!] Captured PPPoE Credentials:
    Username:   testuser
    Password:   testpass
```
