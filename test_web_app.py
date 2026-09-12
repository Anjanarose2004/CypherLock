import os
import io
import unittest
import tempfile
import shutil
from server import app, PRIV_KEY_PATH, PUB_KEY_PATH
from cypher_lock import generate_rsa_keys, force_remove

class TestWebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        cls.client = app.test_client()

    def test_01_status_endpoint(self):
        res = self.client.get('/api/status')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('keys_exist', data)
        self.assertIn('app_dir', data)

    def test_02_key_generation_and_validation(self):
        # Test password complexity rejection
        res = self.client.post('/api/keys/generate', json={'passphrase': 'weak', 'force': True})
        self.assertEqual(res.status_code, 400)

        # Test valid key generation
        valid_pwd = "StrongPassphrase!2026"
        res = self.client.post('/api/keys/generate', json={'passphrase': valid_pwd, 'force': True})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(os.path.exists(PUB_KEY_PATH))
        self.assertTrue(os.path.exists(PRIV_KEY_PATH))

        # Test downloading public key
        res = self.client.get('/api/keys/public/download')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"BEGIN PUBLIC KEY", res.data)

    def test_03_end_to_end_encryption_and_decryption(self):
        # Create temp receiver and sender keys
        temp_dir = tempfile.mkdtemp()
        rec_priv = os.path.join(temp_dir, "rec_priv.pem")
        rec_pub = os.path.join(temp_dir, "rec_pub.pem")
        send_priv = os.path.join(temp_dir, "send_priv.pem")
        send_pub = os.path.join(temp_dir, "send_pub.pem")
        
        pwd = b"SecurePassword!123"
        generate_rsa_keys(rec_priv, rec_pub, pwd)
        generate_rsa_keys(send_priv, send_pub, pwd)

        with open(rec_pub, "rb") as f:
            rec_pub_bytes = f.read()
        with open(send_priv, "rb") as f:
            send_priv_bytes = f.read()
        with open(send_pub, "rb") as f:
            send_pub_bytes = f.read()
        with open(rec_priv, "rb") as f:
            rec_priv_bytes = f.read()

        secret_content = b"Confidential message for testing web edition end to end."

        # 1. Encrypt
        enc_res = self.client.post('/api/encrypt', data={
            'file': (io.BytesIO(secret_content), 'test.txt'),
            'receiver_pub': (io.BytesIO(rec_pub_bytes), 'receiver_pub.pem'),
            'sender_priv': (io.BytesIO(send_priv_bytes), 'sender_priv.pem'),
            'passphrase': pwd.decode('utf-8')
        }, content_type='multipart/form-data')

        self.assertEqual(enc_res.status_code, 200)
        encrypted_bytes = enc_res.data
        self.assertTrue(encrypted_bytes.startswith(b"HYB1"))

        # 2. Decrypt
        dec_res = self.client.post('/api/decrypt', data={
            'file': (io.BytesIO(encrypted_bytes), 'test.txt.enc'),
            'receiver_priv': (io.BytesIO(rec_priv_bytes), 'receiver_priv.pem'),
            'sender_pub': (io.BytesIO(send_pub_bytes), 'sender_pub.pem'),
            'passphrase': pwd.decode('utf-8')
        }, content_type='multipart/form-data')

        self.assertEqual(dec_res.status_code, 200)
        self.assertEqual(dec_res.data, secret_content)
        self.assertEqual(dec_res.headers.get("X-Signature-Verified"), "true")

        # Cleanup
        for path in [rec_priv, rec_pub, send_priv, send_pub]:
            try:
                force_remove(path)
            except Exception:
                pass
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    unittest.main()
