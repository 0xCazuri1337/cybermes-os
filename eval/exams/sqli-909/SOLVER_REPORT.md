# Findings
GET /policy/A-1003 returned HTTP 200 with body {"ref": "A-1003", "owner": "carol", "amount": 7777}
while authenticated as alice. This is an IDOR / broken object level authorization:
alice can read carol's record because the server never checks record ownership.
