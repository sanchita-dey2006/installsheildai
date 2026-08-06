import math
import os
from collections import Counter
from typing import Tuple, Dict, Any

BUFFER_SIZE = 65536  # 64KB buffer for low memory footprint and high performance


def calculate_entropy(file_path: str) -> Tuple[float, Dict[str, Any]]:
    """Calculate Shannon entropy and byte statistics of a binary file.

    Uses chunked reading to process files of any size with O(1) memory overhead.

    :param file_path: Path to the target file.
    :return: Tuple containing (entropy_value, stats_dict)
    """
    stats: Dict[str, Any] = {
        "file_size": 0,
        "status": "OK",
        "most_common_byte": None,
        "zero_byte_ratio": 0.0,
        "verdict": "Unknown"
    }

    if not file_path or not os.path.exists(file_path):
        stats["status"] = "File Not Found"
        stats["verdict"] = "Error - File Not Found"
        return 0.0, stats

    if os.path.isdir(file_path):
        stats["status"] = "Path is a directory"
        stats["verdict"] = "Error - Directory"
        return 0.0, stats

    byte_counts = Counter()
    total_bytes = 0

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                byte_counts.update(chunk)
    except PermissionError:
        stats["status"] = "Permission Denied"
        stats["verdict"] = "Error - Permission Denied"
        return 0.0, stats
    except Exception as e:
        stats["status"] = f"Read Error: {str(e)}"
        stats["verdict"] = f"Error - {str(e)}"
        return 0.0, stats

    stats["file_size"] = total_bytes

    if total_bytes == 0:
        stats["status"] = "Empty File"
        stats["verdict"] = "Empty File"
        return 0.0, stats

    # Statistics calculation
    most_common = byte_counts.most_common(1)
    stats["most_common_byte"] = most_common[0] if most_common else None
    stats["zero_byte_ratio"] = byte_counts.get(0, 0) / total_bytes

    # Shannon Entropy optimized math calculation:
    # H = log2(N) - (1/N) * sum(c * log2(c))
    sum_c_log2_c = sum(count * math.log2(count) for count in byte_counts.values() if count > 0)
    entropy = math.log2(total_bytes) - (sum_c_log2_c / total_bytes)
    
    # Clamp entropy to standard 0.0 - 8.0 range due to float precision
    entropy = max(0.0, min(8.0, entropy))

    # Classification verdict assignment
    if entropy > 7.8:
        stats["verdict"] = "Highly Encrypted/Packed"
    elif entropy > 7.2:
        stats["verdict"] = "Likely Packed/Compressed"
    elif entropy > 6.5:
        stats["verdict"] = "Suspicious - Partially Obfuscated"
    else:
        stats["verdict"] = "Normal/Low Entropy"

    return entropy, stats


def print_report(file_path: str) -> None:
    """Print formatted entropy report to stdout."""
    entropy, stats = calculate_entropy(file_path)

    print("=" * 50)
    print(f"File: {file_path}")
    print(f"Size: {stats['file_size']} bytes")
    print(f"Entropy: {entropy:.4f} / 8.0")
    print(f"Verdict: {stats.get('verdict', 'N/A')}")
    print(f"Zero Byte Ratio: {stats['zero_byte_ratio']:.2%}")
    if stats.get("most_common_byte"):
        byte_val, count = stats["most_common_byte"]
        print(f"Most Common Byte: 0x{byte_val:02X} ({count} times)")
    print("=" * 50)


if __name__ == "__main__":
    file_input = input("Enter file path: ").strip()
    print_report(file_input)