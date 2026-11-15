# B.R.I.C.K. Security Console

The Windows desktop app displays the latest JSON report pushed by a Raspberry Pi
over Ethernet. The browser-only Vite preview uses `src/data/mockReport.json`;
the packaged desktop app starts empty and waits for a live report.
The desktop app counts each accepted inspection report as one USB checked and
persists that total and its good/bad classification counts in the current
Windows user's application data directory. Confidence is calculated as
`good checks / (good checks + bad checks) * 100`; unknown classifications are
excluded, and the face continues to reflect only the latest check. Confidence
is red through 40%, yellow above 40% through 60%, and green above 60%.
Install Node.js https://nodejs.org/en

## Run the desktop app in development

Install dependencies, then run:

```powershell
cd brick-frontend
npm install
npm run desktop:dev
```

## Build the Windows installer

Run on Windows:

```powershell
cd brick-frontend
npm run package:win
```

The NSIS installer is written to `release/`.

## Connect the Raspberry Pi

1. Connect the Pi and PC with Ethernet.
2. Assign unused static IPv4 addresses on the same subnet. For a direct cable,
   for example, use `192.168.50.2/24` for the PC and `192.168.50.1/24` for the
   Pi. A gateway and DNS server are not needed for this direct link.
3. Start B.R.I.C.K. On Windows' firewall prompt, allow the app on the private
   network. If no prompt appears, allow inbound TCP port `8765` from the Pi's
   address in Windows Defender Firewall.
4. In B.R.I.C.K., select the Online/Offline status to open connection details.
   Use the URL listed for the PC's Ethernet adapter and the bearer token shown
   there.
5. After an inspection, have the Pi send the report as an HTTP `POST` with
   `Content-Type: application/json` and
   `Authorization: Bearer <token>`.

The app listens on TCP port `8765` at `/report`. It accepts JSON objects up to
1 MiB from private or link-local network addresses. A successful response is
`200 {"status":"accepted"}`. `GET /health` can be used to check that the
receiver is running.

Example Python sender on the Pi:

```python
import json
from urllib.request import Request, urlopen

PC_URL = "http://192.168.50.2:8765/report"
TOKEN = "paste-the-token-shown-in-the-desktop-app"
REPORT_PATH = "/path/to/inspection-report.json"

with open(REPORT_PATH, encoding="utf-8") as report_file:
    report = json.load(report_file)

request = Request(
    PC_URL,
    data=json.dumps(report).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
    },
    method="POST",
)

with urlopen(request, timeout=10) as response:
    print(response.status, response.read().decode("utf-8"))
```

The receiver token is generated once and stored in the current Windows user's
application data directory. Do not share it or commit it to source control.
