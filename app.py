import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha256

app = Flask(__name__)
app.secret_key = "securevault-secret-key"

# Folders
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"
KEY_FOLDER = "keys"

for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER, KEY_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# ---------- Helper Functions ----------

def pad(data):
    """PKCS7 Padding"""
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    """Remove PKCS7 Padding"""
    return data[:-data[-1]]

# ---------- Routes ----------

@app.route("/")
def index():
    return render_template("index.html")

# ---------- Generate RSA Keys ----------
@app.route("/generate_keys", methods=["GET", "POST"])
def generate_keys():
    if request.method == "POST":
        name = request.form["name"]

        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save keys
        with open(f"{KEY_FOLDER}/{name}_private.pem", "wb") as f:
            f.write(private_key)

        with open(f"{KEY_FOLDER}/{name}_public.pem", "wb") as f:
            f.write(public_key)

        flash("RSA Keys generated successfully!", "success")
        return redirect(url_for("generate_keys"))

    keys = os.listdir(KEY_FOLDER)
    return render_template("generate_keys.html", keys=keys)

# ---------- Encrypt File ----------
@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        file = request.files["file"]
        pubkey_file = request.files["pubkey_file"]

        if not file or not pubkey_file:
            flash("File and Public Key are required!", "danger")
            return redirect(request.url)

        # Save uploaded file
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        data = open(filepath, "rb").read()

        # SHA-256 hash of original
        hash_val = sha256(data).hexdigest()

        # Generate DES key + IV
        des_key = get_random_bytes(8)
        iv = get_random_bytes(8)

        cipher = DES.new(des_key, DES.MODE_CBC, iv)
        enc_data = cipher.encrypt(pad(data))

        # Save encrypted file
        enc_filename = file.filename + ".des.enc"
        enc_path = os.path.join(OUTPUT_FOLDER, enc_filename)
        open(enc_path, "wb").write(iv + enc_data)

        # Encrypt DES key using RSA public key
        pubkey = RSA.import_key(pubkey_file.read())
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        enc_key = cipher_rsa.encrypt(des_key)

        enc_key_filename = file.filename + ".key.enc"
        key_path = os.path.join(OUTPUT_FOLDER, enc_key_filename)
        open(key_path, "wb").write(enc_key)

        flash("File encrypted successfully!", "success")

        return render_template(
            "encrypt.html",
            enc_file=enc_filename,
            enc_key=enc_key_filename,
            hash_val=hash_val
        )

    keys = os.listdir(KEY_FOLDER)
    return render_template("encrypt.html", keys=keys)

# ---------- Decrypt File ----------
@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        enc_file = request.files.get("enc_file")
        enc_key = request.files.get("enc_key")
        privkey_file = request.files.get("privkey_file")

        if not enc_file or not enc_key or not privkey_file:
            flash("All three files are required!", "danger")
            return redirect(request.url)

        # Save uploads
        enc_path = os.path.join(UPLOAD_FOLDER, enc_file.filename)
        key_path = os.path.join(UPLOAD_FOLDER, enc_key.filename)
        priv_path = os.path.join(UPLOAD_FOLDER, privkey_file.filename)

        enc_file.save(enc_path)
        enc_key.save(key_path)
        privkey_file.save(priv_path)

        # Read encrypted DES key
        encrypted_des_key = open(key_path, "rb").read()

        # Decrypt DES key using RSA private key
        try:
            private_key = RSA.import_key(open(priv_path, "rb").read())
            cipher_rsa = PKCS1_OAEP.new(private_key)
            des_key = cipher_rsa.decrypt(encrypted_des_key)
        except Exception as e:
            flash(f"Error decrypting DES key: {e}", "danger")
            return redirect(request.url)

        # Read encrypted file
        enc_data = open(enc_path, "rb").read()
        iv = enc_data[:8]
        ciphertext = enc_data[8:]

        # DES decrypt
        try:
            cipher = DES.new(des_key, DES.MODE_CBC, iv)
            dec_padded = cipher.decrypt(ciphertext)
            dec_data = unpad(dec_padded)
        except Exception as e:
            flash(f"Decryption failed: {e}", "danger")
            return redirect(request.url)

        # Save decrypted file
        output_filename = "decrypted_" + enc_file.filename.replace(".des.enc", "")
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        open(output_path, "wb").write(dec_data)

        # Hash for verification
        computed_hash = sha256(dec_data).hexdigest()

        flash("File decrypted successfully!", "success")

        return render_template(
            "decrypt.html",
            decrypted_file=output_filename,
            hash_val=computed_hash
        )

    # GET request
    return render_template("decrypt.html")

# ---------- Download Output Files ----------
@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)

# ---------- Run App ----------
if __name__ == "__main__":
    app.run(debug=True)
