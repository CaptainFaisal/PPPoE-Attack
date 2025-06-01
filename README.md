## Installation

1. Clone the repository:
```bash
git clone https://github.com/captainfaisal/PPPoE-Attack.git
cd PPPoE-Attack
```

## Usage

### Basic Operation
After connecting the router, run the code to get PPPoE credentials.
```bash
sudo python3 attack.py
```
For specific interface other than eth0, run

```bash
sudo python3 attack.py -i enp4s0
```

### Example Output
```
[+] PPPoE Server running on enp4s0 (MAC: 18:c0:4d:71:32:aa)
[+] Waiting for PPPoE clients...
[+] Received PADI from e8:65:d4:08:75:00
[+] Sent PADO to e8:65:d4:08:75:00
[+] Received PADR from e8:65:d4:08:75:00
[+] Sent PADS (Session ID: 48320)
[+] Received LCP Configuration-Request (ID: 1, Session: 48320)
    MRU: 1480 bytes
[+] Sent LCP Config-Ack (ID: 1, Session: 48320)
[+] Sent LCP Configuration-Request (Session: 48320)
    Magic Number: 0xb01e922e
[+] Received LCP Configuration-Ack (ID: 1, Session: 48320)
[!] Unknown LCP code 9 (Session: 48320)

[!] Captured PAP Credentials:
    Session ID: 48320
    Username:   testuser
    Password:   testpass

[+] Sent PAP ACK
```