#!/usr/bin/env python3
"""TCP is conditional, not a stub listener or a synthetic interoperability pass."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
proof=ROOT/'tests/tcp/real-sender-evidence.json'
if not proof.exists():
    print(json.dumps({'status':'blocked','tcp_enabled':False,
        'reason':'No real latest-UF/HF TCP handshake, framing, ACK and retry proof exists. HTTP acceptance must precede this work.'}))
    sys.exit(2)
raise SystemExit('A supplied file alone is not TCP proof; implement and verify the real scenario before changing this gate.')
