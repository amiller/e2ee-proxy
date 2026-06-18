"""
Live smoke test for verify-then-encrypt: confirms the API serves TD quotes whose
report_data binds the advertised e2e_pubkey, which is what the proxy verifies
before encrypting. Run against a real TEE model.

Usage:
    CHUTES_API_KEY=cpk_... python tests/test_attestation.py [chute_id]
"""

import base64
import hashlib
import os
import secrets
import sys

import requests

API = "https://api.chutes.ai"
LLM = "https://llm.chutes.ai"
H = {"Authorization": f"Bearer {os.environ['CHUTES_API_KEY']}"}

REPORT_DATA_OFF = 48 + 520   # TDX v4: header(48) + body offset(520)
TD_ATTR_OFF = 48 + 120


def first_tee_chute():
    r = requests.get(f"{LLM}/v1/models", headers=H, timeout=30)
    r.raise_for_status()
    for m in r.json()["data"]:
        if m.get("confidential_compute") and m.get("chute_id"):
            return m["chute_id"], m["id"]
    sys.exit("no confidential_compute model in /v1/models")


chute_id = sys.argv[1] if len(sys.argv) > 1 else None
if not chute_id:
    chute_id, name = first_tee_chute()
    print(f"chute: {name}  ({chute_id})")

inst = requests.get(f"{API}/e2e/instances/{chute_id}", headers=H, timeout=30)
inst.raise_for_status()
pubkeys = {i["instance_id"]: i["e2e_pubkey"] for i in inst.json()["instances"]}
print(f"discovered {len(pubkeys)} instance(s)")

nonce = secrets.token_hex(32)
ev = requests.get(
    f"{API}/chutes/{chute_id}/evidence", params={"nonce": nonce}, headers=H, timeout=30
)
ev.raise_for_status()

checked = 0
for e in ev.json()["evidence"]:
    pubkey = pubkeys.get(e["instance_id"])
    if not pubkey:
        continue  # evidence covers more instances than discovery hands out
    quote = base64.b64decode(e["quote"])
    report_data = quote[REPORT_DATA_OFF:REPORT_DATA_OFF + 32].hex()
    expected = hashlib.sha256((nonce + pubkey).encode()).hexdigest()
    debug = quote[TD_ATTR_OFF] & 0x01

    assert report_data == expected, f"{e['instance_id']}: report_data does not bind e2e_pubkey"
    assert not debug, f"{e['instance_id']}: TD in debug mode"
    print(f"  {e['instance_id']}: binding OK, non-debug")
    checked += 1

assert checked > 0, "no discovered instance had matching evidence to check"
print(f"\nAll attestation checks passed ({checked} instance(s)).")
