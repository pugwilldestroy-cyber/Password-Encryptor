#Variables
import hashlib
import tkinter as tk
import tkinter 
import messagebox

#create main window
root = tk.Tk()
root.title("Password Encryptor")
root.geometry("300x150")
root.configure(bg = "lightblue")

#Header
label = tk.Label(root, text="Password Encryptor", font=("Arial", 16))
label.pack(pady=5)
root.configure(bg = "Lightblue")

#input frame
frame = tk.Frame(root)
frame.pack(pady=5)
root.configure(bg = "Lightblue")

#creating the headings for the text boxes
tk.Label(frame, text="password:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
entry_password = tk.Entry(frame, show="*")
entry_password.grid(row=0, column=1, pady=2)

tk.Label(frame, text="Encrypted:").grid(row=1, column=0, sticky="e", padx=5, pady=2)
entry_encrypted = tk.Entry(frame, state="readonly", width=45)
entry_encrypted.grid(row=1, column=1, pady=2)

#first function that enters password

def encrypt_password(password: str) -> str:
    if password is None:
        return None
    return hashlib.sha256(password.encode()).hexdigest()
    
#Checks password against if there is anything there and then changes the text box from readable to editable by the program back to readable and prints a message

def on_check():
    password_value = entry_password.get().strip()
    if not password_value:
        messagebox.showerror("Invalid input", "please enter a password.")
        return
    result = encrypt_password(password_value)
    entry_encrypted.config(state="normal")
    entry_encrypted.delete(0, tk.END)
    entry_encrypted.insert(0, result)
    entry_encrypted.config(state="readonly")
    messagebox.showinfo("Result", "password encrypted successfully")

#button function
btn_check = tk.Button(root, text="Encrypt Password", command=on_check)
btn_check.pack(pady=10)

root.mainloop()
#end of code
