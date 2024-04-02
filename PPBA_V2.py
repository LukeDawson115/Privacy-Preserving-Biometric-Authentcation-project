!pip install TenSEAL
import tenseal as ts

fingerprint_database = {}

def create_context_and_keys():
   
    #Initialises a TenSEAL context with CKKS scheme and generates necessary keys.

    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.generate_galois_keys()
    context.global_scale = 2**40
    return context

def preprocess_biometric_data(data):
    # Example: Assuming the biometric data ranges from 0 to 100.
    # Adjust these min and max values based on your actual data range.
    min_val = 0
    max_val = 100
    
    normalized_data = [(float(i) - min_val) / (max_val - min_val) for i in data]
    return normalized_data


def encrypt_biometric_data(data, context):
  
    #Encrypts biometric data using the provided TenSEAL context.

    encrypted_data = ts.ckks_vector(context, data)
    return encrypted_data.serialize()

def decrypt_data(encrypted_data, context):
    
    #Decrypts the given encrypted data using the provided TenSEAL context.
    
    encrypted_vector = ts.lazy_ckks_vector_from(encrypted_data)
    encrypted_vector.link_context(context)
    decrypted_data = encrypted_vector.decrypt()
    return [round(num, 2) for num in decrypted_data]

def perform_encrypted_operations(encrypted_data, context):
   
    #Performs predefined homomorphic operations on the encrypted data.

    encrypted_vector = ts.lazy_ckks_vector_from(encrypted_data)
    encrypted_vector.link_context(context)
    
    # Example operations
    encrypted_vector.add_(10)
    encrypted_vector.mul_(2)
    
    return encrypted_vector.serialize()

def input_biometric_data():
    
    #Simulates biometric data capture by allowing the user to input a string of 5 integers.
    #Preprocesses the input data for normalization.

    print("Please enter your biometric data as 5 numbers separated by space (each number represents a biometric point):")
    data = list(map(float, input().split()))
    if len(data) != 5:
        print("Invalid input. Please enter exactly 5 numbers.")
        return input_biometric_data()
    
    # Preprocess (normalize) the input data
    preprocessed_data = preprocess_biometric_data(data)
    return preprocessed_data


def store_or_verify_fingerprint(context):
    """
    Determines whether to store a new fingerprint or verify an existing one.
    """            
    global fingerprint_database

    action = input("Do you have a stored fingerprint? (yes/no): ").lower().strip()
    if action == "yes":
        user_id = input("Please enter your User ID: ").strip()
        fingerprint_data = input_biometric_data()
        encrypted_data = encrypt_biometric_data(fingerprint_data, context)
        if user_id in fingerprint_database:
            # Decrypt both the stored and current fingerprint data for comparison
            stored_encrypted_data = fingerprint_database[user_id]
            stored_fingerprint_data = decrypt_data(stored_encrypted_data, context)
            current_fingerprint_data = decrypt_data(encrypted_data, context)
            
            # Now compare the decrypted values (rounded for approximate matching)
            if all(round(stored, 2) == round(current, 2) for stored, current in zip(stored_fingerprint_data, current_fingerprint_data)):
                print("Fingerprint verified successfully.")
            else:
                print("No matching fingerprint found.")
        else:
            print("No user ID found in the database.")
    elif action == "no":
        print_all_user_ids()
        user_id = input("Enter a User ID for your new fingerprint: ").strip()
        fingerprint_data = input_biometric_data()
        encrypted_data = encrypt_biometric_data(fingerprint_data, context)
        fingerprint_database[user_id] = encrypted_data
        print("New fingerprint stored successfully.")
    print_all_user_ids()

def print_all_user_ids():
    """
    Prints all User IDs that are currently stored in the database.
    """
    if fingerprint_database:
        print("User IDs currently stored in the database:")
        for user_id in fingerprint_database.keys():
            print(user_id)
    else:
        print("No fingerprints are currently stored in the database.")

def user_interaction_flow(context):
      while True:
        store_or_verify_fingerprint(context)
        # Ask the user if they want to input another ID
        another_id = input("Would you like to input another ID? (yes/no): ").lower().strip()
        if another_id != "yes":
            break




# Main Function Demonstrating PPBA System

def privacy_preserving_biometric_authentication():
    # Step 1: Context and Key Generation
    context = create_context_and_keys()
    store_or_verify_fingerprint(context)
    """
    Creates a secure context for encryption operations. This step generates a cryptographic context and keys
    needed for the CKKS scheme in TenSEAL, setting the foundation for privacy-preserving computations on the data.
    """
        
    # Step 2: User Inputs Biometric Data
    fingerprint_data = input_biometric_data()
    print("Input Fingerprint Data:", fingerprint_data)
    """
    This section captures the biometric data, which, in a real-world application, would come from biometric sensors
    however, due to consrtaints with biometric applications this simulation purposes, users input a string
    of 5 integers to represent the biometric data, empthasising the need for accurate and secure data capture. 
    """
    
    print("Preprocessing data...")
    """


    Before encryption, preprocessing the data - also called normilisation - is cruical to ensure the data is in a suitable
    form for FHE operations. This step helps aid in maintaining the precision and quality of the biometric data
    throughout the encryption and decrpytion processes, creating the privacy-preserving objectives by preparing data securely for 
    computation.
    """
    
    # Step 3: Encrypt Biometric Data
    encrypted_data = encrypt_biometric_data(fingerprint_data, context)
    print("Your data has been encrypted.")
    """
    This is one of the key phases of the system as it converts the simulated biometric data into its encrpyred format,
    using the CKKS scheme through the TenSEAL library. Encryption is vital for keeping the data secure and keeping privacy,
    as it ensures that sensitive biometric data is transformed into a secure state. 
    """
   
    # Step 4: Perform Homomorphic Operations
    encrypted_data_with_operations = perform_encrypted_operations(encrypted_data, context)
    """
    This step performs operations on encrpyed data without decrpyting it showcasing the power of the
    Fully Homomorphic Encryption (FHE) techinques. This step allows for computation on biometric data
    while keeping the users data secure and private, as the data remains encrpyted even during processing. 
    """
    
    # Step 5: Decrypt Data
    decrypted_data = decrypt_data(encrypted_data_with_operations, context)
    """
    After processing, the encrypted data is decrypted back to aform that can be analysed or compared. 
    This step is crucial for creating insights from encrypted computations, essential in biometric authentication systems
    where the outcome of encrypted computations need to be interpreted. 
    """

    # Step 6: Compare Results
    print("Decrypted Data (after operations):", decrypted_data)
    if all(round(original, 2) == round(decrypted, 2) for original, decrypted in zip(fingerprint_data, decrypted_data)):
        print("Successful: Decrypted output after reversing operations closely matches the original input.")
    else:
        print("Note: The decrypted data may slightly differ from the original due to the approximation nature of the CKKS scheme.")
    """
    Comparing the decrpyted data against known templates or thresholds is fundamental in biometric authnetication
    systems. This comparison determines if the biometric input matches the stored biometric profile, thus authenticating the user.
    """

    """
    This check post-decryption emphasises the challenges of working with encrypted biometric data. It showcases 
    the balance between privacy preservation and the need for accuracy in biometric authentication systems.
    The note on potential discrepancies due to CKKS's approximation nature highlights the limitations and characteristics of the scheme.
    """
    context = create_context_and_keys()
    store_or_verify_fingerprint(context)

if __name__ == "__main__":
    privacy_preserving_biometric_authentication()
