import hashlib
import secrets
import os

ADMIN_PASSWORD = hashlib.md5(f"password-{secrets.token_hex}".encode()).hexdigest()

pastes = {}


def add_paste(paste_id, content, admin_only=False):
    pastes[paste_id] = {
        "content": content,
        "admin_only": admin_only,
    }


add_paste(0, os.getenv("FLAG", "missing flag"), admin_only=True)

# content =
# paste_id = id(content)
a = {"A": "__global__"}

print(a["A"])
print(pastes)
