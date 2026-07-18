
import hashlib

def GetFileHash(path):
    sha256_hash = hashlib.sha256()
    try:
        with open(path, "rb") as file:
            while True:
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
         print(f"(could not hash file: {e})")
    return None

     