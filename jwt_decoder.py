
# jwt_decoder.py
import sys
import json
import argparse
import base64
import hmac
import hashlib
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

class JWTDecoder:
    def __init__(self, token, key=None, color=False):
        self.token = token
        self.key = key
        self.color = color or sys.stdout.isatty()
        self.header = None
        self.payload = None
        self.signature = None
        self.valid_signature = None
        self.is_expired = None
        self.decoded = False

    def decode(self):
        try:
            parts = self.token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format (must have 3 parts)")

            # Decode header
            header_b64 = parts[0]
            header_json = base64.urlsafe_b64decode(header_b64 + '==').decode('utf-8')
            self.header = json.loads(header_json)

            # Decode payload
            payload_b64 = parts[1]
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode('utf-8')
            self.payload = json.loads(payload_json)

            # Signature (raw)
            self.signature = parts[2]

            # Check expiration
            if 'exp' in self.payload:
                exp = datetime.fromtimestamp(self.payload['exp'], tz=timezone.utc)
                now = datetime.now(timezone.utc)
                self.is_expired = now > exp
            else:
                self.is_expired = None

            # Verify signature if key provided
            if self.key:
                self.verify_signature()

            self.decoded = True
        except Exception as e:
            print(Fore.RED + f"Error decoding JWT: {e}")
            sys.exit(1)

    def verify_signature(self):
        # Recreate signature from header and payload
        header_b64 = self.token.split('.')[0]
        payload_b64 = self.token.split('.')[1]
        data = f"{header_b64}.{payload_b64}".encode('utf-8')
        # Assume HS256 (HMAC-SHA256)
        sig = hmac.new(self.key.encode('utf-8'), data, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode('utf-8').rstrip('=')
        self.valid_signature = (sig_b64 == self.signature)

    def to_dict(self):
        return {
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature,
            "valid_signature": self.valid_signature if self.key is not None else None,
            "expired": self.is_expired,
            "token": self.token
        }

    def print(self):
        if self.color:
            print(Fore.GREEN + "Header:")
            for k, v in self.header.items():
                print(f"  {k}: {v}")
            print(Fore.YELLOW + "Payload:")
            for k, v in self.payload.items():
                print(f"  {k}: {v}")
            if self.is_expired is not None:
                if self.is_expired:
                    print(Fore.RED + "  ✗ Token expired")
                else:
                    print(Fore.GREEN + "  ✓ Token valid (not expired)")
            if self.key is not None:
                if self.valid_signature:
                    print(Fore.GREEN + "  ✓ Signature verified")
                else:
                    print(Fore.RED + "  ✗ Signature invalid")
            print(Fore.CYAN + f"Signature: {self.signature}")
        else:
            print("Header:")
            for k, v in self.header.items():
                print(f"  {k}: {v}")
            print("Payload:")
            for k, v in self.payload.items():
                print(f"  {k}: {v}")
            if self.is_expired is not None:
                print(f"  Token {'expired' if self.is_expired else 'valid'}")
            if self.key is not None:
                print(f"  Signature {'verified' if self.valid_signature else 'invalid'}")
            print(f"Signature: {self.signature}")

def main():
    parser = argparse.ArgumentParser(description="JWT Decoder")
    parser.add_argument("token", nargs='?', help="JWT token string")
    parser.add_argument("--key", help="Secret key for HMAC verification")
    parser.add_argument("--file", help="Read JWT from file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--color", action="store_true", help="Force color output")
    args = parser.parse_args()

    token = args.token
    if args.file:
        with open(args.file, 'r') as f:
            token = f.read().strip()

    if not token:
        # Try reading from stdin
        if not sys.stdin.isatty():
            token = sys.stdin.read().strip()
        else:
            print("Error: no token provided")
            sys.exit(1)

    decoder = JWTDecoder(token, args.key, args.color)
    decoder.decode()

    if args.json:
        print(json.dumps(decoder.to_dict(), indent=2))
    else:
        decoder.print()

if __name__ == "__main__":
    main()
