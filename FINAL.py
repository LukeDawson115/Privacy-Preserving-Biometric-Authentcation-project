import logging
import tenseal as ts
import sqlite3
import zlib
import base64
import os
from tkinter import *
from tkinter import messagebox


# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Database and encryption key paths
DATABASE_PATH = 'C:\\Database\\prints-MainW.db'
KEYS_FILE_PATH = 'C:\\Database\\print-key-MainW.bin'

def initialize_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                        user_id TEXT PRIMARY KEY,
                        encrypted_data BLOB
                    )''')
    conn.commit()
    conn.close()
    logging.info("Database initialized.")

def save_to_database(user_id, encrypted_data):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    compressed_data = zlib.compress(encrypted_data)
    encoded_data = base64.b64encode(compressed_data)
    blob_data = sqlite3.Binary(encoded_data)
    cursor.execute("REPLACE INTO fingerprints (user_id, encrypted_data) VALUES (?, ?)", (user_id, blob_data))
    conn.commit()
    conn.close()
    logging.info(f"Data saved for user {user_id}")

def load_from_database(user_id):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_data FROM fingerprints WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        decompressed_data = zlib.decompress(base64.b64decode(row[0]))
        logging.info(f"Data loaded for user {user_id}")
        return decompressed_data
    logging.warning(f"No data found for user {user_id}")
    return None

def perform_encrypted_comparison(encrypted_data1, encrypted_data2, context):
    vector1 = ts.ckks_vector_from(context, encrypted_data1)
    vector2 = ts.ckks_vector_from(context, encrypted_data2)

    # Check if the sizes of the vectors match using the size() method
    if vector1.size() != vector2.size():
        logging.warning("Attempted to compare vectors of different sizes.")
        return False, [], []  # Automatically fail authentication

    difference_vector = vector1 - vector2
    sum_vector = vector1 + vector2
    product_vector = vector1 * vector2
    
    decrypted_differences = difference_vector.decrypt()
    decrypted_sums = sum_vector.decrypt()
    decrypted_products = product_vector.decrypt()

    logging.debug(f"Decrypted differences: {decrypted_differences}")
    logging.debug(f"Decrypted sums: {decrypted_sums}")
    logging.debug(f"Decrypted products: {decrypted_products}")

    return all(abs(diff) < 0.1 for diff in decrypted_differences), decrypted_sums, decrypted_products

def create_context_and_keys():
    if os.path.exists(KEYS_FILE_PATH):
        with open(KEYS_FILE_PATH, 'rb') as key_file:
            context = ts.context_from(key_file.read())
            logging.info("Encryption context loaded from existing keys.")
            return context
    else:
        context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
        context.generate_galois_keys()
        context.global_scale = 2**40
        with open(KEYS_FILE_PATH, 'wb') as key_file:
            key_file.write(context.serialize(save_secret_key=True))
        logging.info("New encryption context and keys generated.")
        return context

context = create_context_and_keys()
initialize_database()

root = Tk()
root.title('Biometric Login')
root.geometry('925x500+300+200')
root.configure(bg='#003366')
root.resizable(False, False)

def signin():
    username = user.get()
    data = [float(x) for x in code.get().split()]
    encrypted_input_data = ts.ckks_vector(context, data).serialize()
    encrypted_stored_data = load_from_database(username)
    if encrypted_stored_data:
        comparison_result, sums, products = perform_encrypted_comparison(encrypted_input_data, encrypted_stored_data, context)
        if comparison_result:
            messagebox.showinfo('Login Success', 'Biometric authentication successful.')
        else:
            messagebox.showerror('Invalid', 'Biometric authentication failed.')
            logging.error(f"Verification failed for user {username}")
    else:
        messagebox.showerror('Invalid', 'No user found with this ID.')

def add():
    window = Toplevel(root)
    window.title("Add User")
    window.geometry('925x500+300+200')
    window.configure(bg='#003366')
    window.resizable(False, False)

    def signup():
        username = user_add.get()
        data = code_add.get()
        data_list = [float(x) for x in data.split()]
        encrypted_data = ts.ckks_vector(context, data_list).serialize()
        save_to_database(username, encrypted_data)
        messagebox.showinfo('Signup', 'Successfully added user.')
        window.destroy()


    
    frame = Frame(window, width=350, height=370, bg='#007FFF')
    frame.place(x=480, y=70)

    heading = Label(frame, text='Add User', fg='#FFFFFF', bg='#007FFF', font=('Microsoft YaHei UI Light', 23, 'bold'))
    heading.place(x=100, y=5)

    user_add = Entry(frame, width=25, fg='#FFFFFF', border=1, bg='#003366', font=('Microsoft YaHei UI Light', 11))
    user_add.place(x=30, y=80)
    user_add.insert(0, 'User ID')
    user_add.bind('<FocusIn>', lambda e: user_add.delete(0, END) if user_add.get() == 'User ID' else None)
    user_add.bind('<FocusOut>', lambda e: user_add.insert(0, 'User ID') if not user_add.get() else None)

    code_add = Entry(frame, width=25, fg='#FFFFFF', border=1, bg='#003366', font=('Microsoft YaHei UI Light', 11))
    code_add.place(x=30, y=150)
    code_add.insert(0, 'Biometric Data')
    code_add.bind('<FocusIn>', lambda e: code_add.delete(0, END) if code_add.get() == 'Biometric Data' else None)
    code_add.bind('<FocusOut>', lambda e: code_add.insert(0, 'Biometric Data') if not code_add.get() else None)

    Button(frame, width=39, pady=7, text='Add User', bg='#57a1f8', fg='white', border=0, command=signup).place(x=35, y=280)

    window.mainloop()

frame = Frame(root, width=350, height=350, bg='#007FFF')
frame.place(x=480, y=70)

heading = Label(frame, text='Login', fg='#FFFFFF', bg='#007FFF', font=('Microsoft YaHei UI Light', 23, 'bold'))
heading.place(x=100, y=5)

user = Entry(frame, width=25, fg='#FFFFFF', border=1, bg='#003366', font=('Microsoft YaHei UI Light', 11))
user.place(x=30, y=80)
user.insert(0, 'User ID')
user.bind('<FocusIn>', lambda e: user.delete(0, END) if user.get() == 'User ID' else None)
user.bind('<FocusOut>', lambda e: user.insert(0, 'User ID') if not user.get() else None)

code = Entry(frame, width=25, fg='#FFFFFF', border=1, bg='#003366', font=('Microsoft YaHei UI Light', 11))
code.place(x=30, y=150)
code.insert(0, 'Biometric Data')
code.bind('<FocusIn>', lambda e: code.delete(0, END) if code.get() == 'Biometric Data' else None)
code.bind('<FocusOut>', lambda e: code.insert(0, 'Biometric Data') if not code.get() else None)

Button(frame, width=39, pady=7, text='Authenticate', bg='#57a1f8', fg='white', border=0, command=signin).place(x=35, y=204)
label=Label(frame,text="Don't have an account?", fg='#FFFFFF', bg='#007FFF', font=('Microsoft YaHei UI Light', 9))
label.place(x=75,y=270)
add_user = Button(frame, width=8, text='Add User', border=1, bg='#003366', cursor='hand2', fg='#FFFFFF', command=add)
add_user.place(x=215, y=270)

root.mainloop()
