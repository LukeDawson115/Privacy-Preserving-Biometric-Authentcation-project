import random
import tenseal as ts

# Functions for file operations.
# These are utility functions that abstract the file I/O operations,
# allowing us to read and write binary data from and to files.
# This is particularly useful for storing encrypted data which is typically
# in a binary format.
def write_data(file_name, data):
    with open(file_name, 'wb') as file:
        file.write(data)

def read_data(file_name):
    with open(file_name, 'rb') as file:
        return file.read()

# Function to simulate fingerprint data capture.
# In a production environment, this function would interface with a biometric sensor to capture
# a fingerprint image or its features. Here, it generates a list of 10 random floating-point numbers
# between 0 and 1 to simulate a fingerprint's unique data points.
def capture_mock_fingerprint_data():
    return [random.uniform(0, 1) for _ in range(10)]

# Function to preprocess fingerprint data.
# This placeholder function represents the step where raw biometric data would
# undergo preprocessing such as normalization, feature extraction, or any other form of
# transformation to make it suitable for encryption and comparison. The current implementation
# simply returns the data as-is, but it's here to illustrate where such preprocessing logic would be inserted.
def preprocess_fingerprint_data(fingerprint_data):
    return fingerprint_data

# Function to create a TenSEAL context.
# This function initializes a TenSEAL context with specific parameters for the CKKS scheme,
# which allows computations on encrypted real numbers. It sets up the scheme, generates the necessary keys,
# and establishes a global scale which is used during encryption and decryption processes.
# The context generated here is a critical component that encapsulates the encryption environment.
def create_context():
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.generate_galois_keys()
    context.global_scale = 2**40
    return context

# Function to encrypt biometric data.
# This function takes the biometric data, which should be a list of floating-point numbers,
# and a TenSEAL context. It uses the context to create a CKKS vector, which is the encrypted
# representation of the biometric data, and then serializes it into a byte stream that can be
# stored or transmitted securely.
def encrypt_biometric_data(data, context):
    encrypted_data = ts.ckks_vector(context, data)
    return encrypted_data.serialize()

# Function to decrypt data.
# This function accepts a serialized CKKS vector and the TenSEAL context used to encrypt it.
# It deserializes the vector, associates it with the context (linking it to the correct encryption parameters
# and keys), and then decrypts it to recover the original floating-point values. The decrypted data is then returned
# for further processing or comparison.
def decrypt_result(encrypted_result, context):
    auth_result = ts.lazy_ckks_vector_from(encrypted_result)
    auth_result.link_context(context)
    decrypted_result = auth_result.decrypt()
    return decrypted_result

# Main function for the PPBA system.
# This is the primary function that coordinates the various steps of the system: starting the process,
# inputting data, encrypting the data, performing secure computations, and optionally decrypting and validating the data.
# It is designed to be user-interactive, with input prompts guiding the user through the process.
# The function demonstrates the potential flow of a biometric authentication system that utilizes FHE for data privacy.
def privacy_preserving_biometric_authentication():
    start = input("Start? (yes/no): ")
    if start.lower() != "yes":
        print("Exited.")
        return

    input_data = input("Do you want to input fingerprint data? (yes/no): ")
    if input_data.lower() == "yes":
        fingerprint_data = list(map(float, input("Input Fingerprint Data (numerical values separated by space): ").split()))
        fingerprint_data = preprocess_fingerprint_data(fingerprint_data)

        encrypt = input("Do you want to encrypt? (yes/no): ")
        if encrypt.lower() == "yes":
            context = create_context()
            encrypted_data = encrypt_biometric_data(fingerprint_data, context)

            user_id = input("Enter user ID for storing the data: ")
            write_data(f'{user_id}_encrypted_fingerprint.txt', encrypted_data)

            # Secure computations are demonstrated here. We perform an addition and a multiplication
            # on the encrypted data. These operations are chosen to show how FHE allows us to compute
            # on ciphertexts. The add_value and mul_value are random numbers that simulate some transformation
            # of the data while it remains encrypted.
            add_value = random.randint(1, 20)
            mul_value = random.randint(1, 5)
            encrypted_vector = ts.lazy_ckks_vector_from(encrypted_data)
            encrypted_vector.link_context(context)
            encrypted_vector.add_(add_value)
            encrypted_vector.mul_(mul_value)
            print(f"Performed addition operation on the encrypted data with value: {add_value}")
            print(f"Performed multiplication operation on the encrypted data with value: {mul_value}")

            decrypt = input("Do you want to decrypt? (yes/no): ")
            if decrypt.lower() == "yes":
                decrypted_data_with_operations = decrypt_result(encrypted_vector.serialize(), context)
                decrypted_data = [round((x / mul_value) - add_value, 5) for x in decrypted_data_with_operations]

                print("Original Fingerprint Data:", fingerprint_data)
                print("Decrypted Data (after reversing the operations):", decrypted_data)

                if all(round(original, 5) == decrypted for original, decrypted in zip(fingerprint_data, decrypted_data)):
                    print("Successful: The decrypted output matches the original input.")
                else:
                    print("Unsuccessful: The decrypted output does not match the original input.")
            else:
                print("Exited without decrypting.")
        else:
            print("Exited without encrypting.")
    else:
        print("Exited without inputting data.")


privacy_preserving_biometric_authentication()
