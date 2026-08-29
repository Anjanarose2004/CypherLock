import os
import sys
import io
import tempfile
import shutil
import datetime
import re
import logging
from flask import Flask, request, jsonify, send_file, render_template, send_from_directory
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag, InvalidSignature

from hybrid_crypto import (
    generate_rsa_keys, encrypt_file, decrypt_file,
    _set_private_key_permissions, _zero_bytearray, force_remove
)

# App directory configuration matching desktop app
APP_DIR = os.path.join(os.path.expanduser("~"), ".hybrid_crypto")
os.makedirs(APP_DIR, exist_ok=True)

PRIV_KEY_PATH = os.path.join(APP_DIR, "private.pem")
PUB_KEY_PATH = os.path.join(APP_DIR, "public.pem")
_log_file = os.path.join(APP_DIR, "hybrid_crypto_errors.log")

logging.basicConfig(
    filename=_log_file,
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("hybrid_crypto_web")

if os.path.exists(_log_file):
    _set_private_key_permissions(_log_file)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB upload limit
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def _validate_pem_public_key_bytes(pub_bytes):
    """Validate public key bytes (must be RSA-3072 PEM)."""
    try:
        if len(pub_bytes) > 16384:
            return None, "File too large (max 16KB for PEM keys)"
        key = serialization.load_pem_public_key(pub_bytes)
        if isinstance(key, rsa.RSAPublicKey) and hasattr(key, 'key_size') and key.key_size == 3072:
            # Calculate SHA-256 fingerprint of public key DER
            der_bytes = key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            digest = hashes.Hash(hashes.SHA256())
            digest.update(der_bytes)
            fingerprint = ":".join(f"{b:02X}" for b in digest.finalize()[:16])
            return key, fingerprint
        return None, "Invalid key: must be an RSA-3072 public key"
    except Exception as e:
        return None, f"Invalid PEM format: {str(e)}"


def _validate_pem_private_key_bytes(content):
    """Verify PEM envelope structure."""
    try:
        if len(content) > 16384:
            return False
        return (
            content.strip().startswith(b"-----BEGIN") and
            b"PRIVATE KEY-----" in content and
            b"-----END" in content
        )
    except Exception:
        return False


def _check_password_complexity(pwd_str):
    """Validate password strength."""
    if len(pwd_str) < 12:
        return False, "Passphrase must be at least 12 characters long."
    if not re.search(r"[A-Z]", pwd_str):
        return False, "Passphrase must contain at least one uppercase letter."
    if not re.search(r"[a-z]", pwd_str):
        return False, "Passphrase must contain at least one lowercase letter."
    if not re.search(r"[0-9]", pwd_str):
        return False, "Passphrase must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", pwd_str):
        return False, "Passphrase must contain at least one special character."
    return True, ""


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def get_status():
    """Return key status and details."""
    has_priv = os.path.exists(PRIV_KEY_PATH)
    has_pub = os.path.exists(PUB_KEY_PATH)
    
    pub_fingerprint = None
    pub_key_content = None
    if has_pub:
        try:
            with open(PUB_KEY_PATH, "rb") as f:
                pub_bytes = f.read(16384)
            _, pub_fingerprint = _validate_pem_public_key_bytes(pub_bytes)
            pub_key_content = pub_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    return jsonify({
        "keys_exist": has_priv and has_pub,
        "has_private_key": has_priv,
        "has_public_key": has_pub,
        "app_dir": APP_DIR,
        "pub_key_path": PUB_KEY_PATH if has_pub else None,
        "priv_key_path": PRIV_KEY_PATH if has_priv else None,
        "pub_fingerprint": pub_fingerprint,
        "public_key_text": pub_key_content
    })


@app.route("/api/keys/public/download", methods=["GET"])
@app.route("/api/keys/public/public.pem", methods=["GET"])
def download_public_key():
    """Download the user's public key."""
    if not os.path.exists(PUB_KEY_PATH):
        return jsonify({"error": "Public key does not exist"}), 404
    with open(PUB_KEY_PATH, "rb") as f:
        key_bytes = f.read()
    response = send_file(
        io.BytesIO(key_bytes),
        as_attachment=True,
        download_name="public.pem",
        mimetype="application/octet-stream"
    )
    response.headers["Content-Disposition"] = 'attachment; filename="public.pem"'
    return response


@app.route("/api/keys/generate", methods=["POST"])
def generate_keys():
    """Generate RSA-3072 keypair with passphrase."""
    data = request.get_json(silent=True) or {}
    passphrase = data.get("passphrase", "")
    force = data.get("force", False)

    if (os.path.exists(PRIV_KEY_PATH) or os.path.exists(PUB_KEY_PATH)) and not force:
        return jsonify({
            "error": "KEY_EXISTS",
            "message": "Keys already exist! Overwriting will permanently prevent decrypting older files."
        }), 409

    valid, msg = _check_password_complexity(passphrase)
    if not valid:
        return jsonify({"error": msg}), 400

    pwd_bytes = bytearray(passphrase.encode("utf-8"))
    try:
        generate_rsa_keys(PRIV_KEY_PATH, PUB_KEY_PATH, bytes(pwd_bytes))
        return jsonify({
            "success": True,
            "message": f"RSA-3072 key pair generated successfully and secured in {APP_DIR}"
        })
    except Exception as e:
        logger.error("Web key generation failed", exc_info=True)
        return jsonify({"error": "Failed to generate keys. Details logged."}), 500
    finally:
        _zero_bytearray(pwd_bytes)


@app.route("/api/keys/change-password", methods=["POST"])
def change_password():
    """Change passphrase of existing private key."""
    data = request.get_json(silent=True) or {}
    old_pwd = data.get("old_passphrase", "")
    new_pwd = data.get("new_passphrase", "")

    if not os.path.exists(PRIV_KEY_PATH):
        return jsonify({"error": "No private key found on system."}), 404

    valid, msg = _check_password_complexity(new_pwd)
    if not valid:
        return jsonify({"error": msg}), 400

    old_pwd_bytes = bytearray(old_pwd.encode("utf-8"))
    new_pwd_bytes = bytearray(new_pwd.encode("utf-8"))

    try:
        with open(PRIV_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=bytes(old_pwd_bytes)
            )

        enc_alg = serialization.BestAvailableEncryption(bytes(new_pwd_bytes))

        temp_key_path = None
        move_succeeded = False
        try:
            out_dir = os.path.dirname(PRIV_KEY_PATH) or "."
            with tempfile.NamedTemporaryFile(delete=False, dir=out_dir, prefix=".hybrid_key_") as temp_key_file:
                temp_key_path = temp_key_file.name
                temp_key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=enc_alg
                ))

            shutil.move(temp_key_path, PRIV_KEY_PATH)
            move_succeeded = True
        finally:
            if not move_succeeded and temp_key_path and os.path.exists(temp_key_path):
                force_remove(temp_key_path)

        _set_private_key_permissions(PRIV_KEY_PATH)
        return jsonify({"success": True, "message": "Passphrase updated successfully!"})

    except (ValueError, TypeError):
        return jsonify({"error": "Incorrect current passphrase."}), 401
    except Exception as e:
        logger.error("Web password change failed", exc_info=True)
        return jsonify({"error": "Failed to update passphrase. Details logged."}), 500
    finally:
        _zero_bytearray(old_pwd_bytes)
        _zero_bytearray(new_pwd_bytes)


@app.route("/api/keys/validate-pem", methods=["POST"])
def validate_pem():
    """Validate uploaded PEM file (public or private)."""
    if "file" not in request.files:
        return jsonify({"valid": False, "error": "No file uploaded"}), 400

    file = request.files["file"]
    key_type = request.form.get("type", "public")
    
    content = file.read(16385)
    if len(content) > 16384:
        return jsonify({"valid": False, "error": "File exceeds 16KB limit"}), 400

    if key_type == "public":
        key, fingerprint = _validate_pem_public_key_bytes(content)
        if key:
            return jsonify({
                "valid": True,
                "type": "public",
                "key_size": key.key_size,
                "fingerprint": fingerprint,
                "filename": secure_filename(file.filename)
            })
        else:
            return jsonify({"valid": False, "error": fingerprint}), 400
    else:
        is_valid = _validate_pem_private_key_bytes(content)
        if is_valid:
            return jsonify({
                "valid": True,
                "type": "private",
                "filename": secure_filename(file.filename)
            })
        else:
            return jsonify({"valid": False, "error": "Invalid PEM private key structure"}), 400


@app.route("/api/encrypt", methods=["POST"])
def encrypt_endpoint():
    """Encrypt and digitally sign a file."""
    if "file" not in request.files:
        return jsonify({"error": "Target file to encrypt is required."}), 400

    target_file = request.files["file"]
    passphrase_str = request.form.get("passphrase", "")
    use_default_priv = request.form.get("use_default_priv", "false").lower() == "true"
    
    temp_dir = tempfile.mkdtemp(prefix="hybrid_enc_")
    pwd_bytes = bytearray(passphrase_str.encode("utf-8")) if passphrase_str else None

    try:
        orig_name = secure_filename(target_file.filename) or "encrypted_file"
        in_path = os.path.join(temp_dir, "input.dat")
        out_path = os.path.join(temp_dir, "output.enc")
        target_file.save(in_path)

        # 1. Receiver's Public Key
        if "receiver_pub" in request.files and request.files["receiver_pub"].filename:
            pub_file = request.files["receiver_pub"]
            pub_bytes = pub_file.read(16385)
            key, fp = _validate_pem_public_key_bytes(pub_bytes)
            if not key:
                return jsonify({"error": f"Invalid receiver public key: {fp}"}), 400
            rec_pub_path = os.path.join(temp_dir, "receiver_pub.pem")
            with open(rec_pub_path, "wb") as f:
                f.write(pub_bytes)
        else:
            return jsonify({"error": "Receiver's public key is required."}), 400

        # 2. Sender's Private Key
        if use_default_priv:
            if not os.path.exists(PRIV_KEY_PATH):
                return jsonify({"error": "Default private key not found. Please generate keys or upload a private key."}), 400
            send_priv_path = PRIV_KEY_PATH
        elif "sender_priv" in request.files and request.files["sender_priv"].filename:
            priv_file = request.files["sender_priv"]
            priv_bytes = priv_file.read(16385)
            if not _validate_pem_private_key_bytes(priv_bytes):
                return jsonify({"error": "Invalid sender private key format."}), 400
            send_priv_path = os.path.join(temp_dir, "sender_priv.pem")
            with open(send_priv_path, "wb") as f:
                f.write(priv_bytes)
        else:
            return jsonify({"error": "Sender's private key is required."}), 400

        # Execute encryption
        encrypt_file(
            rec_pub_path,
            send_priv_path,
            in_path,
            out_path,
            bytes(pwd_bytes) if pwd_bytes else None
        )

        with open(out_path, "rb") as f:
            enc_bytes = f.read()

        enc_filename = f"{orig_name}.enc"
        response = send_file(
            io.BytesIO(enc_bytes),
            as_attachment=True,
            download_name=enc_filename,
            mimetype="application/octet-stream"
        )
        response.headers["Content-Disposition"] = f'attachment; filename="{enc_filename}"'
        response.headers["X-Encrypted-Filename"] = enc_filename
        response.headers["Access-Control-Expose-Headers"] = "X-Encrypted-Filename, Content-Disposition"
        return response

    except OSError:
        logger.error("Web encryption OSError", exc_info=True)
        return jsonify({"error": "Could not access or process file on server."}), 500
    except Exception:
        logger.error("Web encryption failed", exc_info=True)
        return jsonify({"error": "Encryption failed. Ensure correct keys and passphrase were provided."}), 400
    finally:
        if pwd_bytes:
            _zero_bytearray(pwd_bytes)
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.route("/api/decrypt", methods=["POST"])
def decrypt_endpoint():
    """Decrypt and verify digital signature of an encrypted file."""
    if "file" not in request.files:
        return jsonify({"error": "Encrypted file (*.enc) is required."}), 400

    target_file = request.files["file"]
    passphrase_str = request.form.get("passphrase", "")
    use_default_priv = request.form.get("use_default_priv", "false").lower() == "true"
    
    temp_dir = tempfile.mkdtemp(prefix="hybrid_dec_")
    pwd_bytes = bytearray(passphrase_str.encode("utf-8")) if passphrase_str else None

    try:
        orig_name = secure_filename(target_file.filename) or "decrypted_file"
        in_path = os.path.join(temp_dir, "input.enc")
        out_path = os.path.join(temp_dir, "output.dec")
        target_file.save(in_path)

        # 1. Receiver's Private Key
        if use_default_priv:
            if not os.path.exists(PRIV_KEY_PATH):
                return jsonify({"error": "Default private key not found. Please generate keys or upload your private key."}), 400
            rec_priv_path = PRIV_KEY_PATH
        elif "receiver_priv" in request.files and request.files["receiver_priv"].filename:
            priv_file = request.files["receiver_priv"]
            priv_bytes = priv_file.read(16385)
            if not _validate_pem_private_key_bytes(priv_bytes):
                return jsonify({"error": "Invalid receiver private key format."}), 400
            rec_priv_path = os.path.join(temp_dir, "receiver_priv.pem")
            with open(rec_priv_path, "wb") as f:
                f.write(priv_bytes)
        else:
            return jsonify({"error": "Receiver's private key is required."}), 400

        # 2. Sender's Public Key
        if "sender_pub" in request.files and request.files["sender_pub"].filename:
            pub_file = request.files["sender_pub"]
            pub_bytes = pub_file.read(16385)
            key, fp = _validate_pem_public_key_bytes(pub_bytes)
            if not key:
                return jsonify({"error": f"Invalid sender public key: {fp}"}), 400
            send_pub_path = os.path.join(temp_dir, "sender_pub.pem")
            with open(send_pub_path, "wb") as f:
                f.write(pub_bytes)
        else:
            return jsonify({"error": "Sender's public key is required to verify digital signature."}), 400

        # Execute decryption & signature verification
        timestamp = decrypt_file(
            rec_priv_path,
            send_pub_path,
            in_path,
            out_path,
            bytes(pwd_bytes) if pwd_bytes else None
        )

        dt_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')

        with open(out_path, "rb") as f:
            dec_bytes = f.read()

        # Determine download filename
        dec_filename = orig_name.removesuffix(".enc")
        if dec_filename == orig_name:
            dec_filename = f"{orig_name}.decrypted"

        response = send_file(
            io.BytesIO(dec_bytes),
            as_attachment=True,
            download_name=dec_filename,
            mimetype="application/octet-stream"
        )
        response.headers["Content-Disposition"] = f'attachment; filename="{dec_filename}"'
        response.headers["X-Encrypted-Timestamp"] = dt_str
        response.headers["X-Signature-Verified"] = "true"
        response.headers["X-Decrypted-Filename"] = dec_filename
        response.headers["Access-Control-Expose-Headers"] = "X-Encrypted-Timestamp, X-Signature-Verified, X-Decrypted-Filename, Content-Disposition"
        return response

    except InvalidTag:
        return jsonify({"error": "Integrity Error: Decryption failed! The file has been corrupted or tampered with."}), 400
    except InvalidSignature:
        return jsonify({"error": "Signature Error: Digital signature verification failed! File did not originate from this sender public key."}), 400
    except ValueError:
        logger.error("Web decryption ValueError", exc_info=True)
        return jsonify({"error": "Format Error: The encrypted file is corrupted, truncated, or invalid format."}), 400
    except OverflowError:
        return jsonify({"error": "Timestamp Error: File creation timestamp is corrupted or altered."}), 400
    except OSError:
        logger.error("Web decryption OSError", exc_info=True)
        return jsonify({"error": "Could not read or process the encrypted file."}), 500
    except Exception:
        logger.error("Web decryption failed", exc_info=True)
        return jsonify({"error": "Decryption failed. Please verify keys and passphrase."}), 400
    finally:
        if pwd_bytes:
            _zero_bytearray(pwd_bytes)
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f"  Hybrid Cryptography Studio (Web Edition)")
    print(f"  Running locally at: http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=False)
