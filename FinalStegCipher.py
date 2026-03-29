import tkinter as tk
from tkinter import filedialog, messagebox
import os, hashlib, zlib, random, io, hmac, sys
import numpy as np
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- COLORS ---
BG_COLOR = "#080812"
PANEL_COLOR = "#12122b"
ACCENT_ACTIVE = "#00f2ff" 
TEXT_WHITE = "#ffffff"
BTN_PROCESS = "#ff2e63"

class CipherHarshGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("StegCipher-GUI")
        self.root.geometry("700x880")
        self.root.configure(bg=BG_COLOR)
        
        # --- DYNAMIC PATH LOGIC ---
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.logo_path = os.path.join(self.base_path, "logo.png")
        
        # --- WINDOW ICON ---
        if os.path.exists(self.logo_path):
            try:
                icon_img = Image.open(self.logo_path)
                self.icon_photo = ImageTk.PhotoImage(icon_img)
                self.root.iconphoto(False, self.icon_photo)
            except Exception as e:
                print(f"Icon Error: {e}")

        self.img_exts = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heif", ".heic", ".raw", ".cr2", ".nef", ".arw", ".svg", ".ico", ".psd"]
        self.aud_exts = [".mp3", ".wav", ".aac", ".flac", ".alac", ".ogg", ".wma", ".aiff", ".amr", ".mid", ".midi", ".opus"]
        self.vid_exts = [".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".mpeg", ".mpg", ".3gp", ".m4v"]
        
        self.selected_file = None
        self.mode = "ENCODE" 
        self.create_widgets()

    # ====== 🛡️ SECURITY CORE ======
    def get_checksum(self, data, key):
        return hmac.new(key, data, hashlib.sha256).digest()[:16]

    def strip_metadata(self, img):
        data = list(img.getdata())
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(data)
        return clean_img

    def omega_encrypt(self, message, password):
        salt = get_random_bytes(32)
        key = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 100000)[:32]
        prefix_noise = get_random_bytes(random.randint(16, 64))
        suffix_noise = get_random_bytes(random.randint(16, 64))
        msg_bytes = message.encode()
        integrity_hash = self.get_checksum(msg_bytes, key)
        full_payload = prefix_noise + b"|SENTINEL|" + integrity_hash + b"|" + msg_bytes + b"|SENTINEL|" + suffix_noise
        compressed_payload = zlib.compress(full_payload)
        iv = get_random_bytes(16)
        cipher_aes = AES.new(key, AES.MODE_GCM, iv)
        ct_bytes, tag = cipher_aes.encrypt_and_digest(compressed_payload)
        signature = hashlib.sha3_256(password.encode()).digest()[:16] 
        return signature + salt + iv + tag + ct_bytes

    def omega_decrypt(self, data, password):
        try:
            sig_size = 16
            stored_signature = data[:sig_size]
            current_signature = hashlib.sha3_256(password.encode()).digest()[:16]
            if stored_signature != current_signature: return None, "AUTH_FAIL"
            salt = data[16:48]; iv = data[48:64]; tag = data[64:80]; ct = data[80:]
            key = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 100000)[:32]
            cipher_aes = AES.new(key, AES.MODE_GCM, iv)
            decrypted_raw = cipher_aes.decrypt_and_verify(ct, tag)
            full_payload = zlib.decompress(decrypted_raw)
            if b"|SENTINEL|" in full_payload:
                parts = full_payload.split(b"|SENTINEL|")
                inner_data = parts[1]
                stored_hash, actual_msg = inner_data.split(b"|", 1)
                if self.get_checksum(actual_msg, key) == stored_hash:
                    return actual_msg.decode(), "SUCCESS"
            return None, "DECRYPT_ERR"
        except: return None, "DECRYPT_ERR"

    # ====== 🎨 UI SETUP ======
    def create_widgets(self):
        header_frame = tk.Frame(self.root, bg=BG_COLOR)
        header_frame.pack(pady=30)

        if os.path.exists(self.logo_path):
            try:
                raw_logo = Image.open(self.logo_path)
                resized_logo = raw_logo.resize((55, 55), Image.Resampling.LANCZOS)
                self.tk_logo = ImageTk.PhotoImage(resized_logo)
                logo_label = tk.Label(header_frame, image=self.tk_logo, bg=BG_COLOR)
                logo_label.pack(side="left", padx=15)
            except Exception as e:
                print(f"Header Logo Error: {e}")

        tk.Label(header_frame, text="StegCipher-GUI", fg=ACCENT_ACTIVE, bg=BG_COLOR, font=("Impact", 28)).pack(side="left")
        
        m_frame = tk.Frame(self.root, bg=BG_COLOR)
        m_frame.pack(pady=5)
        self.enc_btn = tk.Button(m_frame, text="ENCODE", command=lambda:self.set_mode("ENCODE"), width=15, bg=ACCENT_ACTIVE, font=("Arial", 10, "bold"))
        self.enc_btn.grid(row=0, column=0, padx=10)
        self.dec_btn = tk.Button(m_frame, text="DECODE", command=lambda:self.set_mode("DECODE"), width=15, bg=PANEL_COLOR, fg="white", font=("Arial", 10, "bold"))
        self.dec_btn.grid(row=0, column=1, padx=10)

        self.file_btn = tk.Button(self.root, text="SELECT SOURCE FILE", command=self.select_file, bg="#1a1a3a", fg="white", height=2, font=("Arial", 11, "bold"), relief="flat")
        self.file_btn.pack(fill="x", padx=80, pady=20)
        self.file_lbl = tk.Label(self.root, text="No file selected", fg="#555577", bg=BG_COLOR)
        self.file_lbl.pack()

        input_f = tk.Frame(self.root, bg=PANEL_COLOR, padx=20, pady=20)
        input_f.pack(pady=15, padx=60, fill="x")
        
        tk.Label(input_f, text="MASTER PASSWORD:", fg=TEXT_WHITE, bg=PANEL_COLOR, font=("Arial", 9, "bold")).pack(anchor="w")
        self.pass_entry = tk.Entry(input_f, bg=BG_COLOR, fg=ACCENT_ACTIVE, bd=0, font=("Arial", 12), show="*")
        self.pass_entry.pack(fill="x", pady=5, ipady=8)

        tk.Label(input_f, text="SECRET MESSAGE:", fg=TEXT_WHITE, bg=PANEL_COLOR, font=("Arial", 9, "bold")).pack(anchor="w")
        self.msg_text = tk.Text(input_f, bg=BG_COLOR, fg=TEXT_WHITE, height=5, bd=0)
        self.msg_text.pack(fill="x", pady=5)

        tk.Button(self.root, text="INITIALIZE ENGINE", command=self.handle_process, bg=BTN_PROCESS, fg="white", font=("Arial", 12, "bold"), height=2).pack(fill="x", padx=80, pady=15)

    def set_mode(self, m):
        self.mode = m
        self.enc_btn.config(bg=ACCENT_ACTIVE if m=="ENCODE" else PANEL_COLOR, fg="black" if m=="ENCODE" else "white")
        self.dec_btn.config(bg=ACCENT_ACTIVE if m=="DECODE" else PANEL_COLOR, fg="black" if m=="DECODE" else "white")

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_lbl.config(text=f"Loaded: {os.path.basename(self.selected_file)}")

    def handle_process(self):
        if not self.selected_file: 
            messagebox.showwarning("Warning", "Pehle source file select karein!")
            return
        pwd = self.pass_entry.get()
        if not pwd: 
            messagebox.showwarning("Warning", "Password dalna zaroori hai!")
            return

        if self.mode == "ENCODE":
            msg = self.msg_text.get("1.0", tk.END).strip()
            ext = os.path.splitext(self.selected_file)[1].lower()
            
            # --- FIXED INDIVIDUAL FORMAT FILTER ---
            save_filter = []
            if ext in self.img_exts:
                save_filter.append(("Image Files", "*.png *.jpg *.jpeg *.bmp *.webp"))
            elif ext in self.aud_exts:
                save_filter.append(("Audio Files", "*.mp3 *.wav *.flac *.aac"))
            elif ext in self.vid_exts:
                save_filter.append(("Video Files", "*.mp4 *.mkv *.avi *.mov"))
            
            save_filter.append(("All Files", "*.*"))
            
            save_path = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=save_filter,
                initialfile=f"SECURE_{os.path.basename(self.selected_file)}"
            )
            
            if not save_path: return

            try:
                payload = self.omega_encrypt(msg, pwd)
                if ext in self.img_exts:
                    img = Image.open(self.selected_file).convert('RGB')
                    img = self.strip_metadata(img)
                    img.save(save_path, quality=100)
                    with open(save_path, 'ab') as f: f.write(payload)
                else:
                    with open(self.selected_file, 'rb') as f: data = f.read()
                    with open(save_path, 'wb') as f: f.write(data + payload)
                messagebox.showinfo("Success", "encode Successful")
            except Exception as e:
                messagebox.showerror("Error", f"Encoding failed: {str(e)}")
        else:
            try:
                with open(self.selected_file, 'rb') as f: content = f.read()
                sig = hashlib.sha3_256(pwd.encode()).digest()[:16]
                if sig in content:
                    encrypted_part = content.split(sig)[-1]
                    result, status = self.omega_decrypt(sig + encrypted_part, pwd)
                    if status == "SUCCESS":
                        self.msg_text.delete("1.0", tk.END)
                        self.msg_text.insert("1.0", result)
                        messagebox.showinfo("Success", "decode Successful")
                    else:
                        messagebox.showerror("Denied", "Authentication Failed.")
                else:
                    messagebox.showerror("Error", "No secure data detected.")
            except Exception as e:
                messagebox.showerror("Error", f"Decoding failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherHarshGUI(root)
    root.mainloop()