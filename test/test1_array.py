import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
path = os.path.join(BASE_DIR, 'notebooks', 'Save', 'lgb_url_classifier_metadata.json')  # thay đúng đường dẫn bạn đang dùng
import os
print("Exists:", os.path.exists(path))
print("Size:", os.path.getsize(path), "bytes")

with open(path, "rb") as f:
    raw = f.read(80)
print("80 byte đầu (raw):", raw)