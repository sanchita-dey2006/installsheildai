import re
import os

def extract_strings(file_path, min_len=5):
    """
    File theke printable strings ber kore. min_len = minimum string length
    """
    if not os.path.exists(file_path):
        return []

    strings = []
    pattern = rb"[ -~]{%d,}" % min_len 

    try:
        with open(file_path, "rb") as f:
            data = f.read()
            matches = re.findall(pattern, data)
            strings = [s.decode(errors="ignore") for s in matches]
    except Exception as e:
        print(f"Error: {e}")
        return []

    return strings


if __name__ == "__main__":
    file = input("Enter file path: ").strip()
    result = extract_strings(file)
    
    print(f"\nFound {len(result)} strings\n")
    
    for s in result[:20]:
        print(s)
    if len(result) > 20:
        print(f"...and {len(result)-20} more strings")