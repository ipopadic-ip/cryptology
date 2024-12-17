from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PyPDF2 import PdfReader, PdfWriter
from docx import Document
import os
from tkinter import Tk, filedialog, simpledialog, messagebox
from tkinter import ttk
import tkinter as tk

def generate_rsa_keys():
    """Generiše privatni i javni RSA ključ."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_keys_to_files(private_key, public_key):
    """Čuvanje privatnog i javnog ključa u fajlove."""
    with open("private.pem", "wb") as prv_file:
        prv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    print("Ključevi su sačuvani u 'private.pem' i 'public.pem'.")

def load_keys():
    """Učitavanje privatnog i javnog ključa iz fajlova."""
    try:
        with open("private.pem", "rb") as prv_file:
            private_key = prv_file.read()
        with open("public.pem", "rb") as pub_file:
            public_key = pub_file.read()
        print("Ključevi su uspešno učitani.")
        return private_key, public_key
    except FileNotFoundError:
        messagebox.showerror("Greška", "Ključevi nisu pronađeni. Generišite nove.")
        return None, None

def sign_data(private_key, data):
    """Kreira digitalni potpis za date podatke koristeći privatni ključ."""
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    #generiše potpis koristeći privatni ključ:
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(public_key, data, signature):
    """Verifikuje digitalni potpis koristeći javni ključ."""
    key = RSA.import_key(public_key)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def add_signature_to_pdf(pdf_path, signature):
    """Dodaje digitalni potpis PDF dokumentu kao metapodatak."""
    reader = PdfReader(pdf_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({
        '/Signature': b64encode(signature).decode()
    })
    output_path = f"signed_{os.path.basename(pdf_path)}"
    with open(output_path, "wb") as output_file:
        writer.write(output_file)
    messagebox.showinfo("Uspešno", f"Potpisan PDF sačuvan u: {output_path}")

def add_signature_to_word(docx_path, signature):
    """Dodaje digitalni potpis Word dokumentu kao tekstualni zapis."""
    doc = Document(docx_path)
    doc.add_paragraph("Digital Signature: " + b64encode(signature).decode())
    output_path = f"signed_{os.path.basename(docx_path)}"
    doc.save(output_path)
    messagebox.showinfo("Uspesno", f"Digitalni potpis je dodat Word dokumentu: {output_path}")

def gui_interface():
    root = tk.Tk()
    root.title("Digitalno Potpisivanje")

    def generate_keys():
        private_key, public_key = generate_rsa_keys()
        save_keys_to_files(private_key, public_key)
        messagebox.showinfo("Ključevi generisani", "Privatni i javni ključ su sačuvani.")

    def sign_file():
        file_path = filedialog.askopenfilename(title="Izaberi fajl")
        if not file_path:
            return
        private_key, public_key = load_keys()
        if not private_key:
            return
        with open(file_path, "rb") as file:
            file_data = file.read()
        signature = sign_data(private_key, file_data)
        if file_path.endswith(".pdf"):
            add_signature_to_pdf(file_path, signature)
        elif file_path.endswith(".docx"):
            add_signature_to_word(file_path, signature)
        else:
            messagebox.showwarning("Nepoznat format", "Samo PDF i Word datoteke su podržane.")
    
    ttk.Button(root, text="Generiši Ključeve", command=generate_keys).pack(pady=10)
    ttk.Button(root, text="Potpiši Fajl", command=sign_file).pack(pady=10)
    root.mainloop()

if __name__ == "__main__":
    gui_interface()
