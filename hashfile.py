import hashlib

def compute_file_hash(file_path, algorithm='sha1'):
    """Compute the hash of a file using the specified algorithm."""
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):  # Read the file in chunks of 8192 bytes
            hash_func.update(chunk)

    return hash_func.hexdigest()

def main():
    file_path = input("Enter the path to the file: ")
    algorithm = "sha1"
    
    try:
        file_hash = compute_file_hash(file_path, algorithm)
        print(f"The {algorithm} hash of the file is: {file_hash}")
    except FileNotFoundError:
        print("File not found. Please enter a valid file path.")

if __name__ == "__main__":
    main()