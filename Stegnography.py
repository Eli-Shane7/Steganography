import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from ttkthemes.themed_tk import ThemedTk
from PIL import Image, ImageTk
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

#  User-Defined Password for Encryption 
def generate_key_from_password(password: str, salt: bytes = b'secure_salt'):
    """Generates a secure encryption key from the user's password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

password = "Password123"  # Change this or prompt user input
key = generate_key_from_password(password)
cipher = Fernet(key)

END_MARKER = "1111111111111110"  # Binary End Marker

def encrypt_text(text):
    """Encrypts text using AES-256 encryption."""
    return cipher.encrypt(text.encode())

def decrypt_text(encrypted_text):
    """Decrypts AES-256 encrypted text."""
    try:
        return cipher.decrypt(encrypted_text).decode()
    except Exception as e:
        print("Decryption Error:", str(e))
        return None

def encode_text_into_image(input_text_file, input_image_file, output_image_file):
    """Embeds encrypted text into an image using LSB steganography."""
    with open(input_text_file, "r") as file:
        secret_data = file.read()

    encrypted_data = encrypt_text(secret_data)
    binary_secret_data = ''.join(format(byte, '08b') for byte in encrypted_data) + END_MARKER

    image = cv2.imread(input_image_file)
    if image is None:
        messagebox.showerror("Error", "Invalid image file!")
        return

    max_bytes = image.shape[0] * image.shape[1] * 3 // 8
    if len(binary_secret_data) > max_bytes:
        messagebox.showerror("Error", "Text is too large to fit in the image!")
        return

    data_index = 0
    for row in image:
        for pixel in row:
            for channel in range(3):
                if data_index < len(binary_secret_data):
                    pixel[channel] = (pixel[channel] & ~1) | int(binary_secret_data[data_index])
                    data_index += 1

    cv2.imwrite(output_image_file, image)
    status_label.config(text=f"✅ Encryption Successful! Saved as {output_image_file}", fg="green")
    progress_bar["value"] = 100

def decode_text_from_image(encoded_image_file):
    """Extracts encrypted text from an image and decrypts it."""
    image = cv2.imread(encoded_image_file)
    binary_data = ""

    for row in image:
        for pixel in row:
            for channel in range(3):
                binary_data += str(pixel[channel] & 1)

    if END_MARKER not in binary_data:
        status_label.config(text="❌ No hidden data found!", fg="red")
        return None

    binary_data = binary_data[:binary_data.index(END_MARKER)]

    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    byte_data = bytes([int(byte, 2) for byte in all_bytes])

    decrypted_text = decrypt_text(byte_data)
    if decrypted_text:
        with open("decrypted_text.txt", "w") as file:
            file.write(decrypted_text)
        status_label.config(text="✅ Decryption Successful! Saved as decrypted_text.txt", fg="green")
        return decrypted_text
    else:
        status_label.config(text="❌ Decryption Failed!", fg="red")
        return None

#  Progress Bar 
def update_progress(value):
    progress_bar["value"] = value
    root.update_idletasks()

#  Drag & Drop File Selection
def drop_file(event):
    file_path = event.data
    text_entry.delete(0, tk.END)
    text_entry.insert(0, file_path)

root = ThemedTk(theme="arc")
root.title("Secure Data Hiding in Image Using Steganography")
root.geometry("700x500")

#  Load Background Image
bg_image = Image.open("background.jpg").resize((700, 500), Image.LANCZOS)
bg_photo = ImageTk.PhotoImage(bg_image)

canvas = tk.Canvas(root, width=700, height=500)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, image=bg_photo, anchor="nw")

frame = tk.Frame(root, padx=10, pady=10, bg="#2c2c2c")
frame.place(relx=0.5, rely=0.5, anchor="center")

#  Image Preview
def show_image_preview(image_path):
    img = Image.open(image_path).resize((150, 150))
    img = ImageTk.PhotoImage(img)
    img_label = tk.Label(frame, image=img)
    img_label.image = img
    img_label.grid(row=6, columnspan=3)

#  Select Text File
def select_text_file():
    filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    text_entry.delete(0, tk.END)
    text_entry.insert(0, filename)

#  Select Image File
def select_image_file():
    filename = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    image_entry.delete(0, tk.END)
    image_entry.insert(0, filename)
    show_image_preview(filename)

#  Encrypt Button
def encrypt():
    text_file = text_entry.get()
    image_file = image_entry.get()
    output_file = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])

    if text_file and image_file and output_file:
        for i in range(100):
            update_progress(i)
        encode_text_into_image(text_file, image_file, output_file)
    else:
        status_label.config(text="⚠️ Select both text and image files!", fg="red")

#  Decrypt Button
def decrypt():
    image_file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if image_file:
        for i in range(100):
            update_progress(i)
        decode_text_from_image(image_file)
    else:
        status_label.config(text="⚠️ Select an image file!", fg="red")

#  UI Components
tk.Label(frame, text="Select Text File:", font=("Arial", 12), bg="#2c2c2c", fg="white").grid(row=0, column=0, sticky="w")
text_entry = tk.Entry(frame, width=50)
text_entry.grid(row=0, column=1)
tk.Button(frame, text="Browse", command=select_text_file, bg="#ff9800", fg="white").grid(row=0, column=2)

tk.Label(frame, text="Select Image File:", font=("Arial", 12), bg="#2c2c2c", fg="white").grid(row=1, column=0, sticky="w")
image_entry = tk.Entry(frame, width=50)
image_entry.grid(row=1, column=1)
tk.Button(frame, text="Browse", command=select_image_file, bg="#ff9800", fg="white").grid(row=1, column=2)

encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt, bg="green", fg="white", font=("Arial", 12, "bold"))
encrypt_button.grid(row=2, column=1, pady=10)

decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt, bg="blue", fg="white", font=("Arial", 12, "bold"))
decrypt_button.grid(row=3, column=1, pady=10)

progress_bar = ttk.Progressbar(frame, length=200, mode='determinate')
progress_bar.grid(row=5, columnspan=3, pady=10)

status_label = tk.Label(frame, text="", font=("Arial", 10, "italic"), fg="white", bg="#2c2c2c")
status_label.grid(row=4, columnspan=3, pady=10)

root.mainloop()
