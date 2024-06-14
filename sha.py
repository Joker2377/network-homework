import hashlib
import argparse

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

parser = argparse.ArgumentParser(description="sha256sum")
parser.add_argument('-f', '--file', type=str, help="File Path", default='')
args = parser.parse_args()
file_path = args.file
path1 = './received/'+file_path
path2 = './files/'+file_path

hash1 = compute_sha256sum(path1)
hash2 = compute_sha256sum(path2)
print(f"{path1}: \n{hash1}")
print(f"{path2}: \n{hash2}")
print(f"Match: {hash1 == hash2}")