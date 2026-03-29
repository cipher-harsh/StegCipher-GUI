# 🛡️ StegCipher-GUI

**StegCipher-GUI** is a professional-grade steganography tool designed for secure data hiding within various media formats. It combines industry-standard **AES-256-GCM encryption** with multi-layered security to ensure your private messages remain undetectable and tamper-proof.

## ✨ Key Features
* **Multi-Format Support:** Hide data in Images (.png, .jpg), Audio (.mp3, .wav), and Video (.mp4, .mkv).
* **Military-Grade Encryption:** Uses AES-256-GCM with SHA-512 PBKDF2 key derivation.
* **Metadata Stripping:** Automatically removes EXIF and metadata from images to prevent tracking.
* **Anti-Forensics:** Injects polymorphic noise to defeat statistical analysis.
* **Modern UI:** Sleek, dark-themed interface for a professional experience.

## 🚀 Installation & Usage

1. **Clone the Repo:**

    git clone [https://github.com/cipher-harsh/StegCipher-GUI.git](https://github.com/cipher-harsh/StegCipher-GUI.git)
   
2. Install Dependencies:

    pip install pillow numpy pycryptodome

3. Run the Tool:

    python FinalStegCipher.py

## 🛡️ Security Logic & Architecture

StegCipher-GUI uses a multi-layered "Deep-Shield" architecture to ensure data remains invisible to both the human eye and algorithmic analysis.

### 1. Cryptographic Core
* **AES-256-GCM Encryption:** Every message is encrypted using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM). This provides both **Confidentiality** and **Authenticity**.
* **PBKDF2 Key Derivation:** Your password isn't used directly. We use SHA-512 with 100,000 iterations and a unique 32-byte salt to derive a military-grade key, making brute-force attacks nearly impossible.
* **HMAC Integrity Check:** We generate a 16-byte HMAC (Hash-based Message Authentication Code) to verify that the data hasn't been tampered with.

### 2. Steganographic Layers
* **Polymorphic Noise Injection:** To defeat statistical analysis (like RS Analysis), the tool injects random bytes (noise) before and after the encrypted payload. This breaks the "signature" of the hidden data.
* **Metadata Stripping (Images):** The tool reconstructs the image pixel-by-pixel to strip away all EXIF data, GPS coordinates, and camera serial numbers that could leak your identity.
* **Binary Append (Audio/Video):** For heavy media files, data is injected into the binary structure in a way that doesn't affect the playback quality, keeping it hidden from standard media players.

### 3. Authentication Protocol
* **SHA-3 Signature:** A unique 16-byte signature is derived from your password and stored with the data. During decoding, if this signature doesn't match, the engine refuses to even attempt decryption, protecting against padding oracle attacks.

👤 Author
Harsh Patel (cipher-harsh)

GitHub: cipher-harsh
