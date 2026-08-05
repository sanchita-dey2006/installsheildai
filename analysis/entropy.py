import math
import os
from collections import Counter
from typing import Tuple

def calculate_entropy(file_path: str) -> Tuple[float, dict]:
    """
    File er entropy + byte distribution ber kore
    Returns: (entropy_value, stats_dict)
    Fast because Counter use korechi. Basic.count() slow hoy boro file e
    """
    stats = {
        "file_size": 0,
        "status": "OK",
        "most_common_byte": None,
        "zero_byte_ratio": 0.0
    }

    if not os.path.exists(file_path):
        stats["status"] = "File Not Found"
        return 0.0, stats

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        stats["status"] = f"Read Error: {e}"
        return 0.0, stats

    file_size = len(data)
    stats["file_size"] = file_size

    if file_size == 0:
        stats["status"] = "Empty File"
        return 0.0, stats

    # Fast counting using Counter instead of loop 256 times
    byte_counts = Counter(data)
    stats["most_common_byte"] = byte_counts.most_common(1)[0] if byte_counts else None
    stats["zero_byte_ratio"] = byte_counts.get(0, 0) / file_size

    entropy = 0.0
    for count in byte_counts.values():
        p = count / file_size
        entropy -= p * math.log2(p)

    # Classification add kore dilam
    if entropy > 7.8:
        stats["verdict"] = "Highly Encrypted/Packed"
    elif entropy > 7.2:
        stats["verdict"] = "Likely Packed/Compressed"
    elif entropy > 6.5:
        stats["verdict"] = "Suspicious - Partially Obfuscated"
    else:
        stats["verdict"] = "Normal/Low Entropy"

    return entropy, stats

def print_report(file_path: str):
    """Direct sundor report print korar jonno"""
    entropy, stats = calculate_entropy(file_path)

    print("="*50)
    print(f"File: {file_path}")
    print(f"Size: {stats['file_size']} bytes")
    print(f"Entropy: {entropy:.4f} / 8.0")
    print(f"Verdict: {stats['verdict']}")
    print(f"Zero Byte Ratio: {stats['zero_byte_ratio']:.2%}")
    if stats['most_common_byte']:
        byte, count = stats['most_common_byte']
        print(f"Most Common Byte: 0x{byte:02X} ({count} times)")
    print("="*50)

if __name__ == "__main__":
    file = input("Enter file path: ").strip()
    print_report(file)