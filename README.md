## Install Python Modules

```bash
py -m pip install --upgrade pip
py -m pip install yara-python requests
```

## Usage

```bash
# 1. Save the code below as:
#    ioc_yara_scanner.py

# 2. Create default config:
py ioc_yara_scanner.py init-config

# 3. Download/update enabled feeds:
py ioc_yara_scanner.py update

# 4. Scan a directory:
py ioc_yara_scanner.py scan "C:\Users\AbdulShabazz\Downloads"

# 5. Watch a directory and live-update feeds:
py ioc_yara_scanner.py watch "C:\Users\Abdul\Downloads" --interval 10 --update-interval-min 60

# 6. Run a benign self-test rule:
py ioc_yara_scanner.py self-test

# 7. Create a library snapshot (current working directory)
py ioc_yara_scanner.py preserve . --label pre-bitdefender --zip
```

## Optional: To enable MalwareBazaar sample uploads/exports, get an Auth-Key (auth.abuse.ch), then set:

```bash
setx MALWAREBAZAAR_AUTH_KEY "your_key_here"
```

Then edit `scanner_config.json` and set the MalwareBazaar feed’s **"enabled": true**.

## Library Snapshot

```code
1. Run preserve command.
2. Copy snapshot to external/offline storage.
3. Verify manifest exists and has zero errors.
4. Re-enable Bitdefender.
5. If Bitdefender quarantines anything, compare against manifest SHA-256 values.
6. Restore only known-good project files from the snapshot.
```

**Recommended:** Always copy the reported snapshot folder or ZIP to an external/offline location.

**Minimum files to preserve**

```code
ioc_yara_scanner.py
scanner_config.json
feeds\hashes\local_sha256.txt
custom YARA rules
JSONL scan logs
state.json
ioc_hashes.sqlite3
```
