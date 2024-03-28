import hashlib

def encrypt_password(password):
    password_bytes = password.encode('utf-8')

    # Use SHA-256 hashing algorithm to generate a hash
    hash_object = hashlib.sha256()
    hash_object.update(password_bytes)
    hashed_password = hash_object.hexdigest()

    return hashed_password

if __name__ == "__main__":
    password = input("Enter your password: ")
    encrypted_password = encrypt_password(password)
    print("Encrypted password:", encrypted_password)
