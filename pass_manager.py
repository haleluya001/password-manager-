import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- File paths for salt and passwords ---
SALT_FILE = "salt.key"
PASSWORDS_FILE = "passwords.txt"

def generate_and_save_salt():
    """Generates a new salt and saves it to a file."""
    salt = os.urandom(16) # Generate a random 16-byte salt
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    print(f"New salt generated and saved to {SALT_FILE}")
    return salt

def load_salt():
    """Loads the salt from a file. Generates a new one if not found."""
    if not os.path.exists(SALT_FILE):
        return generate_and_save_salt()
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    return salt

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives a Fernet key from the master password and salt using PBKDF2HMAC.
    """
    # PBKDF2HMAC is a Key Derivation Function (KDF) that securely
    # derives a cryptographic key from a password.
    # It takes the password, salt, a hash function (SHA256), and iterations.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet requires a 32-byte key
        salt=salt,
        iterations=100000, # Higher iterations make it more resistant to brute-force attacks
        backend=default_backend()
    )
    # Derive the key and encode it in URL-safe base64 for Fernet
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def view(fernet_instance: Fernet):
    """
    Views stored passwords.
    Decrypts each password using the provided Fernet instance.
    """
    try:
        with open(PASSWORDS_FILE, "r") as f:
            passwords = f.readlines()
            if not passwords:
                print("No passwords stored.")
                return
            print("\n--- Stored Passwords ---")
            for line in passwords:
                try:
                    name, encrypted_password = line.strip().split(" | ")
                    # Decrypt the password using the Fernet instance
                    decrypted_password = fernet_instance.decrypt(encrypted_password.encode()).decode()
                    print(f"Name: {name}, Password: {decrypted_password}")
                except Exception as e:
                    print(f"Error decrypting a password entry: {line.strip()} - {e}")
            print("------------------------\n")
    except FileNotFoundError:
        print("No password file found. Add a password first.")

def add(fernet_instance: Fernet):
    """
    Adds a new password.
    Encrypts the password using the provided Fernet instance before saving.
    """
    name = input("Enter the name of the password holder: ")
    password = input("Enter the password: ")
    # Encrypt the password using the Fernet instance
    encrypted_password = fernet_instance.encrypt(password.encode()).decode()
    with open(PASSWORDS_FILE, "a") as f:
        f.write(name + " | " + encrypted_password + "\n")
    print(f"Password for '{name}' added successfully.")

# --- Main program logic ---
def run_password_manager():
    """Main function to run the password manager."""
    salt = load_salt()

    # Prompt for master password until correct
    fer = None
    while fer is None:
        master_pwd = input("What is the master password? (This will derive your encryption key): ")
        if not master_pwd:
            print("Master password cannot be empty. Please try again.")
            continue

        try:
            # Derive the Fernet key using the entered master password and the loaded salt
            derived_fernet_key = derive_key(master_pwd, salt)
            fer = Fernet(derived_fernet_key)
            print("Master password accepted. Welcome to your password manager!")
        except Exception as e:
            print(f"Error deriving key or invalid master password. Please try again. Error: {e}")
            fer = None # Reset fer to ensure loop continues

    # Main loop for password manager operations
    while True:
        mode = input("Do you want to add a new password or view existing ones? (add/view), or 'exit' to quit: ").strip().lower()

        if mode == "exit":
            print("Exiting the password manager.")
            break
        elif mode == "view":
            view(fer) # Pass the Fernet instance
        elif mode == "add":
            add(fer) # Pass the Fernet instance
        else:
            print("Invalid mode. Please choose 'add' or 'view'.")
            continue

if __name__ == "__main__":
    run_password_manager()