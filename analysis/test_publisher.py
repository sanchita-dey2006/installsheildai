from signature.verify_signature import verify_signature
from signature.publisher import is_trusted_publisher

path = input("Enter EXE path: ")

result = verify_signature(path)

print(result)

trusted = is_trusted_publisher(result["publisher"])

print("Signature :", result["status"])
print("Publisher :", result["publisher"])
print("Trusted   :", trusted)