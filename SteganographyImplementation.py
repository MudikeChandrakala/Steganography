from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES
import numpy as np
import base64
import hashlib

# ---------- Utility Functions ----------

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt_message(message, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(message)
    encrypted = cipher.encrypt(padded_text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message.encode()))
    return decrypted.decode().strip()

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

# ---------- Hide Data Function ----------

def hide_data(image_path, message, key, output_path='stego_image.png'):
    # Load original image and ensure RGB mode
    img = Image.open(image_path).convert("RGB")

    # Encrypt and prepare binary data
    encoded = encrypt_message(message, key)
    binary_data = text_to_binary(encoded) + '1111111111111110'  # EOF marker

    pixels = np.array(img).astype(np.uint8)
    flat = pixels.flatten()

    if len(binary_data) > len(flat):
        raise ValueError("Message too long to hide in the image.")

    for i in range(len(binary_data)):
        flat[i] = (flat[i] & 0b11111110) | int(binary_data[i])

    new_pixels = flat.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels)
    new_img.save(output_path)

    print("✅ Data hidden successfully in:", output_path)

    # --- Create side-by-side comparison image ---
    original_resized = img.resize((300, 300))
    stego_resized = new_img.resize((300, 300))

    comparison = Image.new('RGB', (600, 300))
    comparison.paste(original_resized, (0, 0))
    comparison.paste(stego_resized, (300, 0))

    # Add labels
    draw = ImageDraw.Draw(comparison)
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except:
        font = ImageFont.load_default()

    draw.text((100, 270), "Original", fill="white", font=font)
    draw.text((400, 270), "Stego", fill="white", font=font)

    comparison.save("comparison.png")
    comparison.show(title="Original vs Stego Image")

# ---------- Extract Data Function ----------

def extract_data(image_path, key):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img).flatten()

    binary_data = ''
    for pixel in pixels:
        binary_data += str(pixel & 1)

    eof = '1111111111111110'
    end = binary_data.find(eof)
    if end != -1:
        binary_data = binary_data[:end]
    else:
        raise ValueError("No hidden message found.")

    encrypted_message = binary_to_text(binary_data)
    return decrypt_message(encrypted_message, key)

# ---------- Main Program ----------

if __name__ == "__main__":
    choice = input("1. Hide\n2. Extract\nEnter choice: ")
    if choice == '1':
        msg = input("Enter message to hide: ")
        pwd = input("Enter encryption key: ")
        hide_data(r"C:\Users\mudik\Desktop\hanuman.png", msg, pwd)
    else:
        pwd = input("Enter decryption key: ")
        try:
            secret = extract_data("stego_image.png", pwd)
            print("🔓 Hidden message:", secret)
        except Exception as e:
            print("❌ Error:", e)
