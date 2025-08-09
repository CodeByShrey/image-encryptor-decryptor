from flask import Flask, render_template_string, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image, UnidentifiedImageError
import io, os

app = Flask(__name__)

# Simple HTML for upload
html = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Image Encryption</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: #f8f9fa;
        }
        .container {
            margin-top: 50px;
        }
        .card {
            border-radius: 15px;
            box-shadow: 0px 4px 15px rgba(0,0,0,0.1);
        }
        .preview {
            max-height: 200px;
            margin-top: 15px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-5">🔒 Secure Image Encryption</h1>
        <div class="row">
            <div class="col-md-6">
                <div class="card p-4">
                    <h4>Encrypt Image</h4>
                    <form method="POST" action="/encrypt" enctype="multipart/form-data">
                        <div class="mb-3">
                            <label class="form-label">Upload Image</label>
                            <input type="file" class="form-control" name="image" accept="image/*" onchange="previewImage(event, 'encryptPreview')" required>
                            <img id="encryptPreview" class="preview img-fluid rounded">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" name="password" placeholder="Enter password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Encrypt</button>
                    </form>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card p-4">
                    <h4>Decrypt Image</h4>
                    <form method="POST" action="/decrypt" enctype="multipart/form-data">
                        <div class="mb-3">
                            <label class="form-label">Upload Encrypted File</label>
                            <input type="file" class="form-control" name="file" accept=".bin" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" name="password" placeholder="Enter password" required>
                        </div>
                        <button type="submit" class="btn btn-success w-100">Decrypt</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

<script>
function previewImage(event, previewId) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const img = document.getElementById(previewId);
            img.src = e.target.result;
            img.style.display = 'block';
        }
        reader.readAsDataURL(file);
    }
}
</script>
</body>
</html>
"""


# Helper functions
def pad(data):
    while len(data) % 16 != 0:
        data += b' '
    return data

def encrypt_image(image_data, password):
    key = password.ljust(32, ' ')[:32].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(image_data))

def decrypt_image(encrypted_data, password):
    key = password.ljust(32, ' ')[:32].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(encrypted_data).rstrip(b' ')

@app.route("/", methods=["GET"])
def index():
    return render_template_string(html)

@app.route("/encrypt", methods=["POST"])
def encrypt():
    image_file = request.files["image"]
    password = request.form["password"]

    img = Image.open(image_file)
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")
    encrypted = encrypt_image(img_bytes.getvalue(), password)

    return send_file(io.BytesIO(encrypted), download_name="encrypted_image.bin", as_attachment=True)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    enc_file = request.files["file"]
    password = request.form["password"]
    encrypted_data = enc_file.read()

    try:
        decrypted = decrypt_image(encrypted_data, password)
        img = Image.open(io.BytesIO(decrypted))
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="PNG")
        return send_file(io.BytesIO(img_bytes.getvalue()), download_name="decrypted_image.png", as_attachment=True)
    except UnidentifiedImageError:
        return """
        <script>
            alert("Incorrect key or corrupted file!");
            window.location.href = "/";
        </script>
        """

if __name__ == "__main__":
    app.run(debug=True)