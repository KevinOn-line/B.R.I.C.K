#Located in /usr/local/bin/usb_monitor_daemon.py & for sudo password is brick
#
#Before hand make sure to run the following commands
#sudo apt update
#sudo apt install -y clamav clamv-daemon pmount python3-pip python3-pyudev
import json 
import os 
import subprocess
import time 
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import pyudev

PC_URL = "http://192.168.137.1:8765/report"
TOKEN = "paste-the-token-shown-in-the-desktop-app" #come back to this
LOG_FILE = "/var/log/usb_malware_daemon.log"

def log_result(msg):
  timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
  line = f"[{timestamp}] {msg}\n"
  print(line.strip())
  try:
    with open(LOG_FILE, "a") as f:
      f.write(line)
  except Exception:
    pass

def send_verdict_to_frontend(partition_name, malicious_verdict, scan_output):
  """Sends an HTTP POST JSON payload to the B.R.I.C.K. desktop app receiver."""
  payload = {
      "device_id": f"pi3-usb-scanner",
      "timestamp": int(time.time()),
      "status": "scanned",
      "malicious": malicious_verdict,  # "YES" or "NO"
      "details": {
          "partition": partition_name,
          "threat_details": scan_output
          if malicious_verdict == "YES"
          else "No threats found",
      },
}

  data_bytes = json.dumps(payload).encode("utf-8")
  headers = {
      "Authorization": f"Bearer {TOKEN}",
      "Content-Type": "application/json",
  }

  request = Request(PC_URL, data=data_bytes, headers=headers, method="POST")

  try:
    with urlopen(request, timeout=5) as response:
      log_result(
          f"Successfully signaled PC frontend! Response: {response.status}"
      )
  except HTTPError as e:
    log_result(f"PC Receiver HTTP Error {e.code}: {e.reason}")
  except URLError as e:
    log_result(f"Connection Error reaching PC frontend: {e.reason}")
  except Exception as e:
    log_result(f"Unexpected error sending to frontend: {e}")

def scan_and_verdict(partition_path):
  dev_name = partition_path.split("/")[-1]
  mount_point = f"/tmp/usb_scan_{dev_name}"
  os.makedirs(mount_point, exist_ok=True)

  log_result(f"New USB partition detected: {partition_path}. Mounting...")

  # Mount read-only safely using pmount
  mount_res = subprocess.run(
      ["pmount", "-r", partition_path, f"usb_scan_{dev_name}"],
      capture_output=True,
  )
  if mount_res.returncode != 0:
    log_result(f"Failed to mount {partition_path}")
    return

  actual_path = f"/media/usb_scan_{dev_name}"
  log_result("Running ClamAV scan...")

  # Run ClamAV scan recursively (-r) and only output infected files (-i)
  scan_res = subprocess.run(
      ["clamscan", "-r", "-i", actual_path], capture_output=True, text=True
  )

  # Unmount drive cleanly
  subprocess.run(["pumount", partition_path], capture_output=True)

  # Determine Yes/No verdict
  if scan_res.returncode == 1:
    malicious_verdict = "YES"
    threat_info = scan_res.stdout.strip()
    log_result(f"Device {partition_path} -> Malicious: YES")
  elif scan_res.returncode == 0:
    malicious_verdict = "NO"
    threat_info = "Clean"
    log_result(f"Device {partition_path} -> Malicious: NO")
  else:
    malicious_verdict = "NO"
    threat_info = f"Scan Warning/Error: {scan_res.stderr.strip()}"
    log_result(f"Device {partition_path} -> Scan completed with warnings")

  # Transmit the verdict signal to the PC frontend
  send_verdict_to_frontend(dev_name, malicious_verdict, threat_info)

  def main():
  log_result("USB Malware Daemon started and listening for hardware events...")
  context = pyudev.Context()
  monitor = pyudev.Monitor.from_context(context)
  monitor.filter_by(subsystem="block", device_type="partition")

  for device in iter(monitor.poll, None):
    if device.action == "add":
      node = device.device_node
      if node and "sd" in node:
        time.sleep(2)  # Give partition time to settle
        scan_and_verdict(node)


if __name__ == "__main__":
  main()