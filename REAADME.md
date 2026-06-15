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
py ioc_yara_scanner.py scan "C:\Users\Abdul\Downloads"

# 5. Watch a directory and live-update feeds:
py ioc_yara_scanner.py watch "C:\Users\Abdul\Downloads" --interval 10 --update-interval-min 60

# 6. Run a benign self-test rule:
py ioc_yara_scanner.py self-test
```

## Optional: To enable MalwareBazaar exports, get an Auth-Key, set:

```bash
setx MALWAREBAZAAR_AUTH_KEY "your_key_here"
```

Then edit `scanner_config.json` and set the MalwareBazaar feed’s **"enabled": true**.