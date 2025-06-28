from dns_utils import *

DOMAIN = 'tunnel.domain.com'
DOMAIN_LABELS_COUNT= DOMAIN.count('.')+1
# Reduced overhead from 30 to 18 (12 bytes saved from IV)
MAX_PLAINTEXT_CHUNK_SIZE = max_plaintext_len(domain_suffix=DOMAIN, id_len=2, overhead=18)
# Server Configuration
SERVER_IP = '127.0.0.1'
SERVER_PORT = 5053
WINDOW_SIZE = 10

MAX_PAYLOAD_2DIG = max_plaintext_len(
    domain_suffix=DOMAIN, id_len=2, overhead=18)  # Reduced overhead
MAX_PAYLOAD_1DIG = max_plaintext_len(
    domain_suffix=DOMAIN, id_len=1, overhead=18)  # Reduced overhead