"""Register the 52 evaluation users (bcrypt-hashed) through the gateway's /auth/register endpoint."""
import requests
users = ["alice", "bob", "charlie", "admin", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory"] + [f"user{i}" for i in range(1, 41)]
for u in users:
    r = requests.post("http://localhost:8000/auth/register", json={"username": u, "password": f"Pw-{u}-2026"})
    print(u, r.status_code)
