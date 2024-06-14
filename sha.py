import hashlib

def compute_sha256sum(file_path):
    # Create a sha256 hash object
    hash_sha256 = hashlib.sha256()

    # Open the file in binary read mode
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)

    # Return the hexadecimal digest of the hash
    return hash_sha256.hexdigest()

file_path = './files/8192.txt'
print(compute_sha256sum(file_path))