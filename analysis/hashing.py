import hashlib
import os

def calculate_hashes(file_path):
    if not os.path.exists(file_path):
        return {"error": "File not found"}

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(8192)  # 8KB chunk
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
    except Exception as e:
        return {"error": str(e)}

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_size": os.path.getsize(file_path)
    }


if __name__ == "__main__":
    file = input("Enter file path: ").strip()
    
    result = calculate_hashes(file)
    
    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print(f"\nFile Size: {result['file_size']} bytes")
        print(f"MD5:    {result['md5']}")
        print(f"SHA1:   {result['sha1']}")
        print(f"SHA256: {result['sha256']}")