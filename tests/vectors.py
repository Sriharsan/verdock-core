"""Appendix A test vectors from draft-sahu-agent-action-receipts-00."""

SEED = bytes([1]) * 32
PUBLIC_KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"

V1_CANONICAL = (
    '{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision",'
    '"params":{"class":"publish","rule_id":"npm-publish","tier":"approve"},'
    '"success":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","user":"alice"}}'
)
V1_SIGNATURE = (
    "ab6afa750440d38f72dc5601f45b1df918de60049b2accbb438dd909"
    "222f42755a534ee67e2eb1397f9d3ca6bd0bf67f1ec078ecc60c08c92438acd2b7dc5802"
)
V1_LINE = (
    '{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision",'
    '"params":{"rule_id":"npm-publish","tier":"approve","class":"publish"},'
    '"success":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","user":"alice"},'
    '"public_key":"' + PUBLIC_KEY + '","signature":"' + V1_SIGNATURE + '"}'
)
V1_SHA256 = "18a2a79ac5e4dcc31172783a0f33efc1518d426c5cf0ccd24982d41c9aa3ee4c"

V2_CANONICAL = (
    '{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval",'
    '"params":{"approver":"alice","decision":"approved","rule_id":"npm-publish"},'
    '"success":true,"ts_ms":1755300012000,"actor":{"agent":"claude-code","user":"alice"},'
    '"prev_hash":"' + V1_SHA256 + '"}'
)
V2_SIGNATURE = (
    "891dc88a6dc93507faca8d52eceb0baf107f325a1b3bb5c60e3e357c"
    "ac86d6ccfd2a0bcf3cee3b7237040483fe1b8c4f049fa72c6a59eb97a22d2c7e97d2cc02"
)
V2_LINE = (
    '{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval",'
    '"params":{"rule_id":"npm-publish","approver":"alice","decision":"approved"},'
    '"success":true,"ts_ms":1755300012000,"actor":{"agent":"claude-code","user":"alice"},'
    '"prev_hash":"' + V1_SHA256 + '","public_key":"' + PUBLIC_KEY + '","signature":"' + V2_SIGNATURE + '"}'
)
