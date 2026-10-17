"""One setup key authorizes only one successful remote enrollment."""
import asyncio
import os
import time
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from starlette.requests import Request

from squirrelops_home_sensor.api import routes_pairing as pairing


def verified_request():
    state = SimpleNamespace()
    ps = pairing._init_pairing_state(state, {})
    shared_key = os.urandom(32)
    for session_id in ("first", "second"):
        ps["sessions"][session_id] = {
            "created_at": time.time(), "verified": True,
            "shared_key": shared_key, "client_name": "Synthetic concurrent client",
        }
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-client")])
    ).sign(key, hashes.SHA256())
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(shared_key).encrypt(
        nonce, csr.public_bytes(serialization.Encoding.PEM), None,
    )
    request = Request({"type": "http", "app": SimpleNamespace(state=state),
                       "client": ("192.0.2.20", 12345)})
    return request, ps, encrypted.hex()


@pytest.mark.parametrize("second_session", ["first", "second"])
async def test_setup_key_cannot_complete_twice_during_database_await(db, second_session):
    request, ps, encrypted = verified_request()
    entered = asyncio.Event()
    release = asyncio.Event()

    class PausedDB:
        async def execute(self, sql, values):
            entered.set()
            await release.wait()
            return await db.execute(sql, values)

        async def commit(self):
            await db.commit()

    async def complete(session_id):
        return await pairing.complete_pairing(
            pairing.CompleteRequest(challenge_id=session_id, encrypted_csr=encrypted),
            request, PausedDB(), {},
        )

    first = asyncio.create_task(complete("first"))
    await asyncio.wait_for(entered.wait(), 2)
    second = asyncio.create_task(complete(second_session))
    await asyncio.sleep(0)  # let the second request reach the concurrent boundary
    release.set()
    results = await asyncio.wait_for(asyncio.gather(first, second, return_exceptions=True), 2)
    rows = await (await db.execute("SELECT id FROM pairing")).fetchall()
    assert len(rows) == 1
    assert sum(isinstance(result, pairing.CompleteResponse) for result in results) == 1
    assert sum(isinstance(result, HTTPException) and result.status_code == 400
               for result in results) == 1
    assert not ps["sessions"]


async def test_cancelled_completion_cannot_reuse_a_key_after_database_commit(db):
    request, ps, encrypted = verified_request()
    committed = asyncio.Event()

    class CancelAfterCommit:
        async def execute(self, sql, values):
            return await db.execute(sql, values)

        async def commit(self):
            await db.commit()
            committed.set()
            await asyncio.Event().wait()

    body = pairing.CompleteRequest(challenge_id="first", encrypted_csr=encrypted)
    task = asyncio.create_task(pairing.complete_pairing(body, request, CancelAfterCommit(), {}))
    await asyncio.wait_for(committed.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(HTTPException) as rejected:
        await pairing.complete_pairing(body, request, db, {})
    assert rejected.value.status_code == 400
    assert len(await (await db.execute("SELECT id FROM pairing")).fetchall()) == 1
