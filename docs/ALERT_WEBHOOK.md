# Alert webhook and Home Assistant events

SquirrelOps Home detects and reports. It never blocks a device, changes a
firewall rule, or touches your router. The response contract exists so that
something you run can: a router or controller API, a Home Assistant automation,
a SIEM, a script. The sensor posts one event per alert, in one documented
shape, optionally signed, and stops there.

Two delivery methods carry the contract:

- **Automation Webhook** (`alert_methods.webhook`): an HTTP POST of the event to
  an endpoint you choose.
- **Home Assistant Events** (`alert_methods.home_assistant`): the same event
  fired as a native Home Assistant event named `squirrelops_alert`, through the
  Home Assistant integration you have already configured for device enrichment.

Both are configured in the app under Settings > Alert Methods, each with its own
minimum severity. Both are off by default.

## When an event is sent

- `alert.new`: a new alert row was created.
- `alert.updated`: an open alert changed in a way a person would notice, which
  means its severity or title changed (for example a decoy connection becoming a
  port scan, or a campaign reaching write activity). Connection-count bumps alone
  do not produce an event. Re-notifications are rate limited to one per five
  minutes per alert.

Delivery is best effort with exponential backoff per method. A failing endpoint
never blocks other methods or the sensor itself.

## Event shape, `squirrelops.alert/1`

```json
{
  "schema": "squirrelops.alert/1",
  "event": "alert.updated",
  "sent_at": "2026-10-19T03:00:04Z",
  "sensor": {"id": "6b1f3c2e-...", "version": "2.1.3"},
  "alert": {
    "id": 42,
    "type": "decoy.trip",
    "severity": "critical",
    "title": "Write activity on Studio Build Mac from 192.168.1.77",
    "summary": "ransomware intent, write activity; 9 connections across 2 ports",
    "created_at": "2026-10-19T03:00:00.000000Z"
  },
  "source": {"ip": "192.168.1.77", "mac": "AA:BB:CC:DD:EE:77", "device_id": 12},
  "decoy": {"id": 7, "name": "Studio Build Mac", "port": 445, "protocol": "tcp"},
  "campaign": {"intent": "ransomware", "stage": 4, "stage_label": "write activity"}
}
```

Field notes:

- `schema` changes only when a field is removed or its meaning changes. New
  optional fields may appear under the same schema; ignore keys you do not know.
- `alert.severity` is one of `low`, `medium`, `high`, `critical`.
- `alert.type` values include `decoy.trip`, `decoy.credential_trip`,
  `device.new`, `device.mac_changed`, `device.verification_needed`, and
  `security.insight`. Automate blocks only on the types you mean to.
- `source.mac` and `source.device_id` are present only when **Include Device
  Identifiers** is on for that method. It is on by default for these two
  methods because the MAC address is what a controller blocks on; turn it off if
  the endpoint is outside your network.
- `decoy` is `null` for alerts that did not come from a decoy. `campaign` is
  `null` unless the deep decoy supplied intent and stage. `stage_label` is
  `null` for a stage number this version does not name.
- `title` is bounded to 256 characters, `summary` to 512, `decoy.name` to 128.
- Nothing else rides along: no event sequence numbers, no read or action
  markers, no raw detail blobs, no credentials.

## HTTP request

```
POST <your endpoint>
Content-Type: application/json
User-Agent: squirrelops-home-sensor/2.1.3
X-SquirrelOps-Schema: squirrelops.alert/1
X-SquirrelOps-Event: alert.updated
X-SquirrelOps-Signature: t=1760000000,v1=<hex>
```

The body is the event as compact JSON with sorted keys. Any 2xx response is
success; anything else is a delivery failure and is retried with backoff.
`http://` and `https://` endpoints are both accepted; a LAN endpoint over
`http://` is fine when combined with a signing secret.

## Verifying the signature

Set a **Signing Secret** in the app and the sensor adds
`X-SquirrelOps-Signature`. The value is `t=<unix seconds>,v1=<hex>` where

```
v1 = HMAC-SHA256(secret, "<t>." + raw_request_body)
```

Verify against the exact bytes you received, compare in constant time, and
reject events whose `t` is older than you are willing to accept (five minutes is
a reasonable window). Python:

```python
import hashlib, hmac, time

def verify(headers, body: bytes, secret: str, max_age: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in headers["X-SquirrelOps-Signature"].split(","))
    if abs(time.time() - int(parts["t"])) > max_age:
        return False
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(parts["v1"], expected)
```

Without a signing secret the header is absent and anyone who can reach your
endpoint can post an event shaped like this one. Do not let an unsigned event
trigger a block.

## Home Assistant

With the Home Assistant integration enabled (URL and long-lived token) and
**Home Assistant Events** turned on, each alert fires an event of type
`squirrelops_alert` whose data is exactly the object above. The sensor only
sends to the configured Home Assistant URL after resolving it to a LAN address,
the same rule the device-enrichment calls follow.

```yaml
automation:
  - alias: Isolate a device that reached write activity on a decoy
    trigger:
      - platform: event
        event_type: squirrelops_alert
    condition:
      - condition: template
        value_template: >
          {{ trigger.event.data.alert.severity == 'critical'
             and trigger.event.data.alert.type == 'decoy.trip'
             and trigger.event.data.source.mac is defined }}
    action:
      - service: notify.mobile_app_your_phone
        data:
          title: "Decoy write activity"
          message: >
            {{ trigger.event.data.alert.title }}
            ({{ trigger.event.data.source.mac }})
      # Add your controller's block service here. The sensor does not block.
```

## Acting on it

The sensor is the witness, not the enforcer. A typical response chain:

1. Receive the event (webhook endpoint, Home Assistant, n8n, a small script).
2. Verify the signature and the age.
3. Decide on `alert.type`, `alert.severity`, and `campaign.stage`. A single
   `decoy.trip` at stage 0 from an unknown device is worth a look; `critical`
   with `stage 4` is worth an immediate isolation.
4. Call your controller with `source.mac` (UniFi, Omada, OPNsense and similar
   all block or isolate by MAC or by the client it maps to). Keep the block
   list in the controller, where you can see and undo it.
5. Keep the event. It is the record of what the decoy saw.

A device you have marked as a **trusted scanner** does not raise decoy-trip
alerts and therefore produces no event; credential trips still do.

## Secrets and privacy

The endpoint URL and signing secret are stored in the sensor's encrypted secret
store and redacted in every configuration response, like the Slack webhook URL.
What leaves your network is listed in the user guide's data table: for this
method, exactly the fields above, to the endpoint you configured.
