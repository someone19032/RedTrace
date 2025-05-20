# RedTrace
This is an IP tool that I made, if you need help with smth then contacr @kao_someone on Discord AKA Bintyzz
includes: 
[1] IP Geolookup
    → Looks up geographical info about an IP using ip-api.com.
      Includes country, region, city, ISP, etc.
[2] Create Grabber
    → Executes either 'CreateGrabber.py' or 'MoreInfoGrabber.py'
      depending on Simple/Advanced choice. Likely for IP logging.
[3] Check My IP
    → Displays your public IP address using ipify.org.
[4] IP Generator
    → Generates random *public* IPv4 addresses.
      Optionally sends them to a Discord webhook.
[5] Scan IPs
    → Scans your local subnet (e.g., 192.168.0.1–254) for active hosts.
[6] Port Scanner
    → Scans common ports (21, 22, 80, 443, etc.) on a given IP.
      Uses PowerShell TCP connections.
[7] Reverse DNS
    → Performs a reverse DNS lookup on an IP address via nslookup.
[8] WHOIS Lookup
    → Runs nslookup on a domain (incomplete; doesn't use a WHOIS service).
[9] DNS Lookup
    → Also uses nslookup to resolve a domain (incomplete).
[10] Subnet Calculator
    → Not implemented. (No corresponding label exists.)
[11] Proxy Check
    → Not implemented. (No corresponding label exists.)
[12] Port Range Scan
    → Not implemented. (No corresponding label exists.)
[13] IP Reputation
    → Queries AbuseIPDB for IP abuse reports using an API key.
      Requires you to input your AbuseIPDB API key manually.
[14] Speed Test
    → Not implemented. (No corresponding label exists.)
[15] WiFi Passwords
    → Shows saved WiFi profiles and their passwords.
      Also displays current WiFi password and LAN IP.
[16] MAC Changer
    → Asks for a new MAC but doesn't change it.
      Just disables/enables WiFi adapter without applying the MAC.
[17] Tor Check
    → Checks if your current IP appears in the Tor exit node list.
[18] HTTP Headers
    → Sends a HEAD request (`curl -I`) to a given URL to show headers.
[19] Connections
    → Shows all active TCP connections via `netstat -ano`.
[20] Hosts Editor
    → Opens the system's hosts file in Notepad for editing.
[21] VPN Test
    → Checks your IP with ipinfo.io and queries Akamai's DNS resolver.
      Intended to help verify if a VPN or DNS leak is active.
[22] Locate Private IPs
    → Prompts for local subnet prefix (e.g., 192.168.0.) and pings 1–254.
      Displays live hosts on the LAN.
[23] Help
    → Displays this help section.
[24] Exit
    → Closes the tool.
