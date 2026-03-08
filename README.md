# ShieldScan — Antivirus & Malware Detection Tool

Ethical Hacking & Cyber Security Individual Project

---

## Features
- **Signature detection** — SHA-256 hash lookup against threat database
- **Pattern matching** — Aho-Corasick Trie scans file bytes for known malicious strings
- **Heuristic analysis** — entropy, PE headers, packer signatures, script indicators
- **Real-time monitoring** — watchdog-powered directory surveillance
- **AES-256-GCM quarantine** — encrypted vault for isolated threats
- **Custom data structures** — HashTable (FNV-1a), PatternTrie, PriorityQueue (max-heap)

---

## Quick Start (3 steps)

### Step 1 — Install Python
Download Python 3.9+ from https://www.python.org/downloads/
- **Windows**: tick "Add Python to PATH" during install
- **macOS**: `brew install python3`
- **Linux**: `sudo apt install python3 python3-pip`

### Step 2 — Install dependencies
Open a terminal / command prompt in the ShieldScan folder:
```bash
pip install -r requirements.txt
```

On Linux you may also need tkinter:
```bash
sudo apt install python3-tk
```

### Step 3 — Run ShieldScan
```bash
python main.py
```
The GUI window will open immediately.

---

## How to Use

### Dashboard
The home screen shows protection status, key statistics (files scanned,
threats found, quarantined files), and recent threats table.

### Running a Scan
1. Click **Scan** in the sidebar
2. Choose a scan type:
   - **Quick Scan** — scans Desktop, Downloads, Documents
   - **Full Scan**  — scans your entire home directory
   - **Custom**     — choose any folder
3. Click **▶ Start Scan**
4. Right-click any threat row → **Quarantine Selected**

### Quarantine
- Lists all quarantined files (AES-256-GCM encrypted)
- **Restore** — decrypts and returns file to original location
- **Delete Permanently** — irreversibly removes the file

### Real-Time Protection
1. Go to **Settings**
2. Set a directory to monitor (default: Downloads)
3. Check **Enable real-time file monitoring**
4. A popup will alert you when a threat is detected

### Running Tests
```bash
pytest tests/ -v
```
Expected: all tests pass (25+ unit + integration tests)

---

## Project Structure
```
ShieldScan/
├── main.py                  # GUI entry point
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── hash_table.py        # Custom HashTable (FNV-1a, open addressing)
│   ├── pattern_trie.py      # Custom Trie + Aho-Corasick multi-pattern search
│   ├── priority_queue.py    # Custom max-heap PriorityQueue
│   ├── engine.py            # Scan engine (signature + pattern + heuristic)
│   ├── quarantine.py        # AES-256-GCM quarantine vault
│   ├── monitor.py           # Real-time file monitor (watchdog)
│   └── database.py          # SQLite database layer
├── tests/
│   └── test_shieldscan.py   # Unit + integration tests (pytest)
└── data/
    ├── shieldscan.db        # SQLite database (auto-created)
    ├── .dbkey               # AES master key (auto-generated, do not share)
    └── quarantine/          # Encrypted vault files (.qvault)
```

---

## Notes
- The `.dbkey` file is auto-generated on first run — keep it safe.
  Without it, quarantined files cannot be decrypted.
- ShieldScan uses a demo signature database seeded with EICAR test hashes
  and simulated threat signatures for academic demonstration.
- No files are sent over the network — all scanning is local.
