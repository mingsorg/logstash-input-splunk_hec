# Conditional TCP feasibility: not qualified

T8 follows HTTP acceptance. There is no TCP listener, enable switch or support claim.
The current sender evidence is `httpout` over HTTP through a recording relay to
verified plugin HTTPS and the real HEC oracle. It does not establish `tcpout`
handshakes, compression negotiation, TCP framing, ACK/retry behavior or reconnects.

An initial bounded capture attempt is retained in
[`tcp-capture.json`](../tests/tcp/evidence/tcp-capture.json). Its UF container did
not reach healthy status within the 600-second startup deadline, so that run does
not establish handshake, framing or acknowledgment behavior. No TCP support is
inferred from the successful HTTP sender tests.

[`tests/tcp/capture.py`](../tests/tcp/capture.py) provides a transparent recording
relay for a subsequent spike against an owned real indexer. It retains at most
4 MiB of payload, 4,096 observations and 16 active relay connections, and
distinguishes transport observation from qualification. Run it
inside the interop driver with `--receiver <oracle-bridge-ip>:9997`; use the latest
pinned images and only a test oracle owned by that run.

Before implementation, capture pinned latest UF and HF TCP traffic against a real
Splunk receiver, establish handshake/record/ACK boundaries, induce stalls and
reconnects, and verify the proposed receiver's retry behavior with source identities.
Only then can a disabled-by-default listener be considered. Synthetic frames or an
HTTP ACK test cannot satisfy this gate. `tests/tcp/check.py` reports absent evidence
as blocked (exit 2), never as a skipped passing interoperability test.
