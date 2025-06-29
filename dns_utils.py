def max_base32_payload_len(domain_suffix="tunnel.domain.com", id_len=2):
    MAX_FQDN_LEN = 253
    MAX_LABEL_LEN = 63

    fixed_len = id_len + 1  # ID + dot
    for label in domain_suffix.split("."):
        fixed_len += len(label) + 1  # each label + dot

    remaining = MAX_FQDN_LEN - fixed_len

    # How many full 63-char labels fit?
    num_labels = remaining // (MAX_LABEL_LEN + 1)  # +1 for dot between each
    leftover = remaining % (MAX_LABEL_LEN + 1)

    # Can we squeeze in a partial label (if leftover allows)?
    extra = min(leftover, MAX_LABEL_LEN)

    # total number of base32 characters you can fit
    return num_labels * MAX_LABEL_LEN + extra


def max_plaintext_len(domain_suffix="tunnel.domain.com", id_len=2 , overhead=18):
    base32_len = max_base32_payload_len(domain_suffix, id_len)
    # total allowed encrypted packet size
    total_packet_bytes = (base32_len * 5) // 8
    max_plaintext = total_packet_bytes - overhead  # subtract encryption overhead
    return max_plaintext


def encode_base32_dns_query(base32_string: str, id_str="00", domain_suffix="tunnel.domain.com"):
    MAX_LABEL_LEN = 63

    if not base32_string.isalnum():
        raise ValueError("Base32 string must be alphanumeric only")

    # Split into DNS-safe labels
    chunks = [base32_string[i:i + MAX_LABEL_LEN]
              for i in range(0, len(base32_string), MAX_LABEL_LEN)]

    labels = [id_str] + chunks + domain_suffix.split(".")
    fqdn = ".".join(labels)

    if len(fqdn) > 253:
        raise ValueError(f"Resulting FQDN too long: {len(fqdn)} > 253")

    return fqdn
