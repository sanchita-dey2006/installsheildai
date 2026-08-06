from signature.verify_signature import verify_signature

path = input("Enter file path: ")

result = verify_signature(path)

print(result)