"""Integration tests for pairing routes: challenge, HMAC verify, HKDF, cert exchange, full flow."""
import asyncio
import hashlib
import hmac
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import seed_pairing


class TestPairingChallenge:
    """GET /pairing/code/challenge -- initiate pairing."""

    def test_challenge_returns_200(self, client):
        response = client.get("/pairing/code/challenge")
        assert response.status_code == 200

    def test_challenge_returns_required_fields(self, client):
        response = client.get("/pairing/code/challenge")
        data = response.json()
        assert "challenge" in data
        assert "sensor_id" in data
        assert "sensor_name" in data

    def test_challenge_is_32_bytes_hex(self, client):
        response = client.get("/pairing/code/challenge")
        data = response.json()
        challenge_bytes = bytes.fromhex(data["challenge"])
        assert len(challenge_bytes) == 32

    def test_challenge_sensor_id_matches_config(self, client, sensor_config):
        response = client.get("/pairing/code/challenge")
        data = response.json()
        assert data["sensor_id"] == sensor_config["sensor_id"]

    def test_challenge_sensor_name_matches_config(self, client, sensor_config):
        response = client.get("/pairing/code/challenge")
        data = response.json()
        assert data["sensor_name"] == sensor_config["sensor_name"]

    def test_challenge_different_each_call(self, client):
        r1 = client.get("/pairing/code/challenge")
        r2 = client.get("/pairing/code/challenge")
        assert r1.json()["challenge"] != r2.json()["challenge"]


class TestPairingVerify:
    """POST /pairing/verify -- HMAC verification and HKDF key derivation."""

    def _get_challenge_and_code(self, client, app):
        """Helper: get challenge and extract the current pairing code from app state."""
        response = client.get("/pairing/code/challenge")
        data = response.json()
        challenge_hex = data["challenge"]
        # Access the pairing code from the app's pairing state
        pairing_state = app.state.pairing_state
        code = pairing_state["code"]
        return challenge_hex, code

    def _compute_hmac(self, challenge_hex: str, code: str) -> str:
        challenge_bytes = bytes.fromhex(challenge_hex)
        return hmac.new(
            code.encode("utf-8"), challenge_bytes, hashlib.sha256
        ).hexdigest()

    def test_verify_correct_hmac_returns_200(self, client, app):
        challenge_hex, code = self._get_challenge_and_code(client, app)
        hmac_response = self._compute_hmac(challenge_hex, code)
        response = client.post(
            "/pairing/verify",
            json={
                "response": hmac_response,
                "client_nonce": os.urandom(32).hex(),
                "client_name": "Test MacBook",
            },
        )
        assert response.status_code == 200

    def test_verify_returns_encrypted_ca_cert(self, client, app):
        challenge_hex, code = self._get_challenge_and_code(client, app)
        hmac_response = self._compute_hmac(challenge_hex, code)
        response = client.post(
            "/pairing/verify",
            json={
                "response": hmac_response,
                "client_nonce": os.urandom(32).hex(),
                "client_name": "Test MacBook",
            },
        )
        data = response.json()
        assert "encrypted_ca_cert" in data
        assert "server_nonce" in data

    def test_verify_server_nonce_is_32_bytes(self, client, app):
        challenge_hex, code = self._get_challenge_and_code(client, app)
        hmac_response = self._compute_hmac(challenge_hex, code)
        response = client.post(
            "/pairing/verify",
            json={
                "response": hmac_response,
                "client_nonce": os.urandom(32).hex(),
                "client_name": "Test MacBook",
            },
        )
        data = response.json()
        nonce_bytes = bytes.fromhex(data["server_nonce"])
        assert len(nonce_bytes) == 32

    def test_verify_wrong_hmac_returns_403(self, client, app):
        client.get("/pairing/code/challenge")
        response = client.post(
            "/pairing/verify",
            json={
                "response": "0" * 64,
                "client_nonce": os.urandom(32).hex(),
                "client_name": "Test MacBook",
            },
        )
        assert response.status_code == 403

    def test_verify_increments_failure_count(self, client, app):
        client.get("/pairing/code/challenge")
        for _ in range(3):
            client.post(
                "/pairing/verify",
                json={
                    "response": "0" * 64,
                    "client_nonce": os.urandom(32).hex(),
                    "client_name": "Test MacBook",
                },
            )
        pairing_state = app.state.pairing_state
        assert pairing_state["failed_attempts"] >= 3

    def test_verify_max_5_failures_regenerates_code(self, client, app):
        client.get("/pairing/code/challenge")
        original_code = app.state.pairing_state["code"]
        for _ in range(5):
            client.post(
                "/pairing/verify",
                json={
                    "response": "0" * 64,
                    "client_nonce": os.urandom(32).hex(),
                    "client_name": "Test MacBook",
                },
            )
        new_code = app.state.pairing_state["code"]
        assert new_code != original_code

    def test_verify_without_challenge_returns_400(self, client, app):
        """Verify should fail if no challenge was issued."""
        # Clear any existing pairing state challenge
        if hasattr(app.state, "pairing_state"):
            app.state.pairing_state["challenge"] = None
        response = client.post(
            "/pairing/verify",
            json={
                "response": "0" * 64,
                "client_nonce": os.urandom(32).hex(),
                "client_name": "Test MacBook",
            },
        )
        assert response.status_code == 400


class TestPairingComplete:
    """POST /pairing/complete -- encrypted CSR exchange, cert signing."""

    def _do_challenge_and_verify(self, client, app):
        """Helper: run challenge + verify, return shared_key and pairing state."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        # Step 1: challenge
        challenge_resp = client.get("/pairing/code/challenge")
        challenge_hex = challenge_resp.json()["challenge"]
        sensor_id = challenge_resp.json()["sensor_id"]
        code = app.state.pairing_state["code"]

        # Step 2: verify
        client_nonce = os.urandom(32)
        hmac_response = hmac.new(
            code.encode("utf-8"), bytes.fromhex(challenge_hex), hashlib.sha256
        ).hexdigest()

        verify_resp = client.post(
            "/pairing/verify",
            json={
                "response": hmac_response,
                "client_nonce": client_nonce.hex(),
                "client_name": "Test MacBook",
            },
        )
        assert verify_resp.status_code == 200

        # Derive shared key (same as sensor does)
        challenge_bytes = bytes.fromhex(challenge_hex)
        ikm = code.encode("utf-8") + challenge_bytes + client_nonce
        shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sensor_id.encode("utf-8"),
            info=b"squirrelops-pairing-v1",
        ).derive(ikm)

        return shared_key, verify_resp.json()

    def test_complete_returns_200(self, client, app):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        shared_key, verify_data = self._do_challenge_and_verify(client, app)

        # Generate client keypair and CSR
        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MacBook")]))
            .sign(client_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        # Encrypt CSR with shared key
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        encrypted_csr = aesgcm.encrypt(nonce, csr_pem, None)

        response = client.post(
            "/pairing/complete",
            json={"encrypted_csr": (nonce + encrypted_csr).hex()},
        )
        assert response.status_code == 200

    def test_complete_returns_encrypted_client_cert(self, client, app):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        shared_key, verify_data = self._do_challenge_and_verify(client, app)

        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MacBook")]))
            .sign(client_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        encrypted_csr = aesgcm.encrypt(nonce, csr_pem, None)

        response = client.post(
            "/pairing/complete",
            json={"encrypted_csr": (nonce + encrypted_csr).hex()},
        )
        data = response.json()
        assert "encrypted_client_cert" in data

    def test_complete_client_cert_is_decryptable(self, client, app):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        shared_key, verify_data = self._do_challenge_and_verify(client, app)

        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MacBook")]))
            .sign(client_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        encrypted_csr = aesgcm.encrypt(nonce, csr_pem, None)

        response = client.post(
            "/pairing/complete",
            json={"encrypted_csr": (nonce + encrypted_csr).hex()},
        )
        data = response.json()

        # Decrypt the client cert
        encrypted_cert_bytes = bytes.fromhex(data["encrypted_client_cert"])
        cert_nonce = encrypted_cert_bytes[:12]
        cert_ciphertext = encrypted_cert_bytes[12:]
        cert_pem = aesgcm.decrypt(cert_nonce, cert_ciphertext, None)
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test MacBook"

    def test_complete_stores_pairing_record(self, client, app, db):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        shared_key, verify_data = self._do_challenge_and_verify(client, app)

        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MacBook")]))
            .sign(client_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        encrypted_csr = aesgcm.encrypt(nonce, csr_pem, None)

        client.post(
            "/pairing/complete",
            json={"encrypted_csr": (nonce + encrypted_csr).hex()},
        )

        # Verify pairing record was stored
        cursor = asyncio.get_event_loop().run_until_complete(
            db.execute("SELECT * FROM pairing WHERE client_name = 'Test MacBook'")
        )
        row = asyncio.get_event_loop().run_until_complete(cursor.fetchone())
        assert row is not None
        assert row["client_name"] == "Test MacBook"
        assert row["client_cert_fingerprint"].startswith("sha256:")

    def test_complete_invalidates_code(self, client, app):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        shared_key, verify_data = self._do_challenge_and_verify(client, app)

        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MacBook")]))
            .sign(client_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)
        encrypted_csr = aesgcm.encrypt(nonce, csr_pem, None)

        client.post(
            "/pairing/complete",
            json={"encrypted_csr": (nonce + encrypted_csr).hex()},
        )

        # The code should be invalidated -- a new challenge should give a fresh code
        pairing_state = app.state.pairing_state
        assert pairing_state.get("code_invalidated") is True or pairing_state.get("challenge") is None


class TestPairingFullFlow:
    """End-to-end: challenge -> verify -> complete -> authenticated request."""

    def test_full_pairing_flow(self, client, app, db):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # Step 1: Challenge
        challenge_resp = client.get("/pairing/code/challenge")
        assert challenge_resp.status_code == 200
        challenge_hex = challenge_resp.json()["challenge"]
        sensor_id = challenge_resp.json()["sensor_id"]
        code = app.state.pairing_state["code"]

        # Step 2: Verify
        client_nonce = os.urandom(32)
        hmac_response = hmac.new(
            code.encode("utf-8"), bytes.fromhex(challenge_hex), hashlib.sha256
        ).hexdigest()

        verify_resp = client.post(
            "/pairing/verify",
            json={
                "response": hmac_response,
                "client_nonce": client_nonce.hex(),
                "client_name": "Test MacBook",
            },
        )
        assert verify_resp.status_code == 200

        # Derive shared key
        ikm = code.encode("utf-8") + bytes.fromhex(challenge_hex) + client_nonce
        shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sensor_id.encode("utf-8"),
            info=b"squirrelops-pairing-v1",
        ).derive(ikm)

        # Decrypt CA cert
        encrypted_ca = bytes.fromhex(verify_resp.json()["encrypted_ca_cert"])
        aesgcm = AESGCM(shared_key)
        ca_cert_pem = aesgcm.decrypt(encrypted_ca[:12], encrypted_ca[12:], None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        assert "SquirrelOps" in ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Step 3: Complete
        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MacBook")]))
            .sign(client_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        nonce = os.urandom(12)
        encrypted_csr = aesgcm.encrypt(nonce, csr_pem, None)

        complete_resp = client.post(
            "/pairing/complete",
            json={"encrypted_csr": (nonce + encrypted_csr).hex()},
        )
        assert complete_resp.status_code == 200

        # Decrypt client cert
        encrypted_cert = bytes.fromhex(complete_resp.json()["encrypted_client_cert"])
        client_cert_pem = aesgcm.decrypt(encrypted_cert[:12], encrypted_cert[12:], None)
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
        assert client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test MacBook"

        # Verify the client cert was signed by the CA
        ca_public_key = ca_cert.public_key()
        # This should not raise
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA as _ECDSA
        from cryptography.hazmat.primitives import hashes as _hashes
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            _ECDSA(_hashes.SHA256()),
        )


class TestUnpair:
    """DELETE /pairing/{id} -- requires auth."""

    def test_unpair_returns_200(self, client, db):
        pairing_id = asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        response = client.delete(f"/pairing/{pairing_id}")
        assert response.status_code == 200

    def test_unpair_removes_record(self, client, db):
        pairing_id = asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        client.delete(f"/pairing/{pairing_id}")
        cursor = asyncio.get_event_loop().run_until_complete(
            db.execute("SELECT * FROM pairing WHERE id = ?", (pairing_id,))
        )
        row = asyncio.get_event_loop().run_until_complete(cursor.fetchone())
        assert row is None

    def test_unpair_nonexistent_returns_404(self, client, db):
        response = client.delete("/pairing/9999")
        assert response.status_code == 404
