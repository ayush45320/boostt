import uuid
import json
from datetime import datetime, timedelta

# Define the file path globally
FILE_PATH = "data/keys/keys.json"

def main_menu():
    """Display the main menu and handle user input."""
    while True:
        print("\n1. Generate Key")
        print("2. List Keys")
        print("3. Delete Key")
        print("4. Clear File")
        print("5. Exit")

        choice = input("Enter your choice: ")
        handle_choice(choice)

def handle_choice(choice):
    """Process user choice and call appropriate functions."""
    if choice == "1":
        handle_key_generation()
    elif choice == "2":
        handle_list_keys()
    elif choice == "3":
        handle_delete_key()
    elif choice == "4":
        handle_clear_file()
    elif choice == "5":
        print("Exiting program.")
        exit_program()
    else:
        print("Invalid choice. Please try again.")

def handle_key_generation():
    """Handle key generation process."""
    month = int(input("Enter month (e.g., 1 or 3): "))
    amount = int(input("Enter amount: "))
    quantity = int(input("Enter quantity of keys: "))
    keys = load_keys_from_file(FILE_PATH)
    generate_key(keys, month, amount, quantity, FILE_PATH)

def handle_list_keys():
    """Handle listing all keys."""
    keys = load_keys_from_file(FILE_PATH)
    print("All Keys:", list_keys(keys))

def handle_delete_key():
    """Handle deleting a key."""
    keys = load_keys_from_file(FILE_PATH)
    key_to_delete = input("Enter the key to delete: ")
    delete_key(keys, key_to_delete)
    print("Key deleted.")

def handle_clear_file():
    """Handle clearing all keys from the file."""
    clear_file(FILE_PATH)
    print("File cleared.")

def load_keys_from_file(file_path):
    """Load keys from a JSON file."""
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        return []

def save_keys_to_file(keys, file_path):
    """Save keys to a JSON file."""
    with open(file_path, "w") as file:
        json.dump(keys, file, indent=4)

def generate_key(keys, month, amount, quantity, file_path):
    """Generate new keys and save them to the file."""
    new_keys = [{"key": str(uuid.uuid4()), "month": month, "amount": amount} for _ in range(quantity)]
    keys.extend(new_keys)
    save_keys_to_file(keys, file_path)

def list_keys(keys):
    """Return the list of keys."""
    return keys

def delete_key(keys, key):
    """Delete a specific key from the list."""
    updated_keys = [key_data for key_data in keys if key_data["key"] != key]
    save_keys_to_file(updated_keys, FILE_PATH)

def clear_file(file_path):
    """Clear all keys from the file."""
    save_keys_to_file([], file_path)

def exit_program():
    """Exit the program."""
    print("Exiting program.")
    exit()

if __name__ == "__main__":
    main_menu()
