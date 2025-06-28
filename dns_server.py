import os
import random
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
from threading import Lock
from crypto_module import GCMDecryptor
from utils import DOMAIN, DOMAIN_LABELS_COUNT, SERVER_IP, SERVER_PORT

class TunnelResolver(BaseResolver):
    def __init__(self):
        self.window_size = 10
        self.expected_seq = 0  # lowest unprocessed in-order seq
        self.received = {}     # seq -> base32 str
        self.lock = Lock()
        self.decryptor = GCMDecryptor()
        self.handshake_complete = False

    def resolve(self, request, handler):
        qname = str(request.q.qname).strip('.')
        parts = qname.split('.')
        reply = request.reply()

        # Check for handshake message (format: "counter.hello.domain")
        if len(parts) >= 3 and parts[1] == "hello":
            try:
                initial_counter = int(parts[0])
                self.decryptor.set_initial_counter(initial_counter)
                self.handshake_complete = True
                print(f"[*] Handshake complete. Initial counter: {initial_counter}")
                # Send ACK with special IP pattern 1.1.1.1
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.1.1.1"), ttl=0))
                return reply
            except ValueError:
                pass

        # Normal packet processing
        if not self.handshake_complete:
            print("[!] Received data before handshake completed")
            return reply

        try:
            seq = int(parts[0])
        except ValueError:
            print("[!] Invalid sequence number in query:", parts[0])
            return reply

        base32_data = ''.join(parts[1:-DOMAIN_LABELS_COUNT])

        with self.lock:
            if not self.in_window(seq):
                print(f"[!] Out-of-window SEQ {seq:02d} (expected {self.expected_seq:02d})")
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.build_ack_ip(self.expected_seq)), ttl=0))
                return reply

            if seq not in self.received:
                self.received[seq] = base32_data

            ip = self.build_ack_ip((seq+1)%100)

            while self.expected_seq in self.received:
                b32 = self.received.pop(self.expected_seq)
                try:
                    decrypted = self.decryptor.decrypt(b32)
                    print(f"[SEQ {self.expected_seq:02d}] Decrypted: {decrypted}")
                    with open("received.txt", "a", encoding="utf-8") as f:
                        f.write(decrypted)
                except Exception as e:
                    print(f"[SEQ {self.expected_seq:02d}] Decryption failed: {e}")
                    break
                else:
                    self.expected_seq = (self.expected_seq + 1) % 100
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=0))

        return reply

    def in_window(self, seq):
        """Returns True if seq is within [expected_seq, expected_seq + window_size)"""
        delta = (seq - self.expected_seq + 100) % 100
        return delta < self.window_size

    def build_ack_ip(self, seq: int) -> str:
        """Generate IP in form: rand.rand.seq.rand"""
        return f"{random.randint(1, 254)}.{random.randint(0, 254)}.{seq}.{random.randint(1, 254)}"

# Start the DNS server
os.remove('./received.txt') if os.path.exists('./received.txt') else None
resolver = TunnelResolver()
server = DNSServer(resolver, port=SERVER_PORT, address=SERVER_IP, tcp=False)
print(f"[*] DNS tunnel server listening on UDP {SERVER_IP}:{SERVER_PORT}")
server.start()