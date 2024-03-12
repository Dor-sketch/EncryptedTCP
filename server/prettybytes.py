import binascii
import re
from termcolor import colored

def pretty_bytes(data: bytes, bytes_per_row=32, max_repeats=8) -> str:
    hex_str = binascii.hexlify(data).decode("utf-8")

    spaced_str = " ".join(hex_str[i: i + 2] for i in range(0, len(hex_str), 2))

    # Abbreviate repeated 00 bytes
    repeated_zero_byte_pattern = re.compile(r"(?:00 ){%d,}" % max_repeats)
    abbreviated_str = repeated_zero_byte_pattern.sub(".... ", spaced_str)

    # Highlight non-zero bytes for added emphasis and color the ellipsis blue
    non_zero_byte_pattern = re.compile(r"([0-9a-f]{2}|\.\.\.\. )")
    colored_str = non_zero_byte_pattern.sub(
        lambda m: colored(m.group(1), "green")
        if m.group(1) != ".... "
        else colored(m.group(1), "blue"),
        abbreviated_str,
    )

    row_length = 3 * bytes_per_row  # 2 characters per byte + 1 space
    rows = [
        colored_str[i: i + row_length] for i in range(0, len(colored_str), row_length)
    ]
    if len(rows) > 100:
        rows = rows[:100]
        rows.append("...\n\033[0mAborting output after 100 rows")
    return "\n".join(rows)
