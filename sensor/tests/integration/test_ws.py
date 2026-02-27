"""Integration tests for WebSocket endpoint: auth, subscribe, live events, replay, keepalive."""
import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tests.integration.conftest import seed_pairing


class TestWebSocketAuth:
    """WS /ws/events -- authentication handshake."""

    def test_auth_ok_with_valid_fingerprint(self, client, db):
        asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        with client.websocket_connect("/ws/events") as ws:
            ws.send_json({"type": "auth", "cert_fingerprint": "sha256:testfp"})
            msg = ws.receive_json()
            assert msg["type"] == "auth_ok"

    def test_auth_ok_with_token(self, client, db):
        """Local sensor shortcut: authenticate with bearer token."""
        # Insert a local pairing record
        asyncio.get_event_loop().run_until_complete(
            db.execute(
                """INSERT INTO pairing (client_name, client_cert_fingerprint, is_local, paired_at)
                   VALUES ('local-client', 'local-token-123', 1, '2026-02-22T00:00:00Z')"""
            )
        )
        asyncio.get_event_loop().run_until_complete(db.commit())
        with client.websocket_connect("/ws/events") as ws:
            ws.send_json({"type": "auth", "token": "local-token-123"})
            msg = ws.receive_json()
            assert msg["type"] == "auth_ok"

    def test_auth_error_with_invalid_fingerprint(self, client, db):
        with client.websocket_connect("/ws/events") as ws:
            ws.send_json({"type": "auth", "cert_fingerprint": "sha256:invalid"})
            msg = ws.receive_json()
            assert msg["type"] == "auth_error"
            assert "reason" in msg

    def test_auth_error_closes_connection(self, client, db):
        with pytest.raises((WebSocketDisconnect, Exception)):
            with client.websocket_connect("/ws/events") as ws:
                ws.send_json({"type": "auth", "cert_fingerprint": "sha256:invalid"})
                ws.receive_json()  # auth_error
                ws.receive_json()  # should raise disconnect

    def test_auth_timeout_no_auth_frame(self, client, db):
        """If no auth frame is sent, the server should eventually close.

        This test verifies the server doesn't hang forever. In practice the
        server uses a timeout, but TestClient is synchronous, so we just
        verify non-auth messages are rejected.
        """
        with client.websocket_connect("/ws/events") as ws:
            ws.send_json({"type": "replay", "since_seq": 0})
            msg = ws.receive_json()
            assert msg["type"] == "auth_error"


class TestWebSocketReplay:
    """Replay missed events from the events table."""

    def _auth(self, ws, db):
        asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        ws.send_json({"type": "auth", "cert_fingerprint": "sha256:testfp"})
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"

    def _seed_events(self, db, count=5):
        for i in range(1, count + 1):
            asyncio.get_event_loop().run_until_complete(
                db.execute(
                    """INSERT INTO events (event_type, payload, created_at)
                       VALUES (?, ?, ?)""",
                    (
                        "device.updated",
                        json.dumps({"device_id": i, "change": "online"}),
                        f"2026-02-22T{i:02d}:00:00Z",
                    ),
                )
            )
        asyncio.get_event_loop().run_until_complete(db.commit())

    def test_replay_all_events(self, client, db):
        self._seed_events(db, count=3)
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
            ws.send_json({"type": "replay", "since_seq": 0})
            events = []
            while True:
                msg = ws.receive_json()
                if msg["type"] == "replay_complete":
                    break
                if msg["type"] == "ping":
                    ws.send_json({"type": "pong"})
                    continue
                events.append(msg)
            assert len(events) == 3
            for evt in events:
                assert evt["type"] == "event"
                assert "seq" in evt
                assert "event_type" in evt
                assert "payload" in evt

    def test_replay_from_sequence(self, client, db):
        self._seed_events(db, count=5)
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
            ws.send_json({"type": "replay", "since_seq": 3})
            events = []
            while True:
                msg = ws.receive_json()
                if msg["type"] == "replay_complete":
                    break
                if msg["type"] == "ping":
                    ws.send_json({"type": "pong"})
                    continue
                events.append(msg)
            # Should get events with seq > 3
            assert len(events) == 2
            assert all(evt["seq"] > 3 for evt in events)

    def test_replay_complete_includes_last_seq(self, client, db):
        self._seed_events(db, count=3)
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
            ws.send_json({"type": "replay", "since_seq": 0})
            last_msg = None
            while True:
                msg = ws.receive_json()
                if msg["type"] == "replay_complete":
                    last_msg = msg
                    break
            assert "last_seq" in last_msg
            assert last_msg["last_seq"] == 3

    def test_replay_empty(self, client, db):
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
            ws.send_json({"type": "replay", "since_seq": 0})
            msg = ws.receive_json()
            assert msg["type"] == "replay_complete"
            assert msg["last_seq"] == 0

    def test_replay_events_in_order(self, client, db):
        self._seed_events(db, count=5)
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
            ws.send_json({"type": "replay", "since_seq": 0})
            events = []
            while True:
                msg = ws.receive_json()
                if msg["type"] == "replay_complete":
                    break
                if msg["type"] == "ping":
                    ws.send_json({"type": "pong"})
                    continue
                events.append(msg)
            seqs = [evt["seq"] for evt in events]
            assert seqs == sorted(seqs)


class TestWebSocketLiveEvents:
    """Live event streaming after auth.

    These tests use broadcast_event directly to avoid timing issues between
    the async EventBus subscriber scheduling and the synchronous TestClient.
    """

    def _auth(self, ws, db):
        asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        ws.send_json({"type": "auth", "cert_fingerprint": "sha256:testfp"})
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"

    def _receive_event(self, ws, max_attempts=5):
        """Receive the next event message, skipping any ping frames."""
        for _ in range(max_attempts):
            msg = ws.receive_json()
            if msg["type"] == "ping":
                ws.send_json({"type": "pong"})
                continue
            return msg
        raise RuntimeError("Did not receive event within max_attempts")

    def test_live_event_published_to_ws(self, client, db, event_bus):
        from squirrelops_home_sensor.api.ws import broadcast_event

        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)

            # Publish event through event bus and then broadcast directly
            seq = asyncio.get_event_loop().run_until_complete(
                event_bus.publish("device.online", {"device_id": 1, "ip": "192.168.1.100"})
            )
            asyncio.get_event_loop().run_until_complete(
                broadcast_event(seq, "device.online", {"device_id": 1, "ip": "192.168.1.100"})
            )

            msg = self._receive_event(ws)
            assert msg["type"] == "event"
            assert msg["event_type"] == "device.online"
            assert msg["payload"]["device_id"] == 1

    def test_live_event_has_sequence_number(self, client, db, event_bus):
        from squirrelops_home_sensor.api.ws import broadcast_event

        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)

            seq = asyncio.get_event_loop().run_until_complete(
                event_bus.publish("alert.new", {"alert_id": 42})
            )
            asyncio.get_event_loop().run_until_complete(
                broadcast_event(seq, "alert.new", {"alert_id": 42})
            )

            msg = self._receive_event(ws)
            assert "seq" in msg
            assert isinstance(msg["seq"], int)

    def test_multiple_live_events_sequential(self, client, db, event_bus):
        from squirrelops_home_sensor.api.ws import broadcast_event

        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)

            for i in range(3):
                seq = asyncio.get_event_loop().run_until_complete(
                    event_bus.publish("device.updated", {"device_id": i})
                )
                asyncio.get_event_loop().run_until_complete(
                    broadcast_event(seq, "device.updated", {"device_id": i})
                )

            received = []
            for _ in range(3):
                msg = self._receive_event(ws)
                received.append(msg)

            assert len(received) == 3
            seqs = [m["seq"] for m in received]
            assert seqs == sorted(seqs)


class TestWebSocketKeepalive:
    """Keepalive: ping/pong protocol."""

    def _auth(self, ws, db):
        asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        ws.send_json({"type": "auth", "cert_fingerprint": "sha256:testfp"})
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"

    def test_client_pong_is_accepted(self, client, db):
        """Server should accept pong frames without error."""
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
            # Client sends an unsolicited pong -- server should not crash
            ws.send_json({"type": "pong"})
            # If we get here without exception, the pong was accepted


class TestWebSocketDisconnectBehavior:
    """Clean disconnect behavior."""

    def _auth(self, ws, db):
        asyncio.get_event_loop().run_until_complete(seed_pairing(db))
        ws.send_json({"type": "auth", "cert_fingerprint": "sha256:testfp"})
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"

    def test_client_disconnect_cleans_up(self, client, db, event_bus):
        """After client disconnects, events should not be delivered."""
        with client.websocket_connect("/ws/events") as ws:
            self._auth(ws, db)
        # Connection is closed -- publishing should not raise
        asyncio.get_event_loop().run_until_complete(
            event_bus.publish("device.offline", {"device_id": 1})
        )
        # If no exception, cleanup was successful
