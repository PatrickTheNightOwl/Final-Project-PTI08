import json
import os 

USERDATA = "userdata.json"

def load_data():
    if not os.path.exists(USERDATA) or os.path.getsize(USERDATA) == 0:
        # Nếu file không tồn tại hoặc rỗng, trả về dict trống
        return {}
    with open(USERDATA, "r") as f:
        return json.load(f)  # load file json cho 1 biến

def save_data(data):
    with open(USERDATA, "w") as f:
        json.dump(data, f, indent=4)  # lưu dữ liệu vào json bằng cách truyền dữ liệu vào hàm
