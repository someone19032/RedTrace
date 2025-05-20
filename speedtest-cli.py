import os
import subprocess
import sys
import time

def run_speedtest():
    # Clear screen (compatible with both Windows and Unix)
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("\n" + "="*40)
    print("   NETWORK SPEED TEST")
    print("="*40 + "\n")
    
    try:
        # Try multiple ways to run speedtest
        commands = [
            ["speedtest-cli", "--simple"],  # Standard installation
            ["python", "-m", "speedtest", "--simple"],  # Module format
            ["python", "speedtest-cli.py", "--simple"],  # Local file
            ["speedtest", "--simple"]  # Some installations use this
        ]
        
        success = False
        for cmd in commands:
            try:
                print(f"Trying: {' '.join(cmd)}...")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30  # Add timeout to prevent hanging
                )
                if result.stdout:
                    print("\n" + "="*40)
                    print(result.stdout.strip())
                    print("="*40 + "\n")
                    success = True
                    break
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        if not success:
            print("\nERROR: Could not run speed test.")
            print("Please install speedtest-cli first:")
            print("  pip install speedtest-cli\n")
    
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}\n")
    
    # Wait for user input (like batch pause)
    input("Press Enter to return to main menu...")
    return

if __name__ == "__main__":
    run_speedtest()