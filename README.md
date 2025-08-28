# NX Payload Detector

A Node.js security tool to detect and remove malicious artifacts left by compromised NX packages on npm.

## Background

Multiple popular NX packages were compromised on npm with malicious code that:
- Harvests sensitive files (wallets, keys, environment variables)
- Steals GitHub and npm tokens
- Creates inventory files in `/tmp`
- Adds shutdown commands to shell configuration files
- Exfiltrates data to attacker-controlled GitHub repositories

Affected packages include: nx, @nx/workspace, @nx/js, @nx/key, @nx/node, @nx/enterprise-cloud, @nx/eslint, @nx/devkit

Compromised versions: 21.5.0, 20.9.0, 20.10.0, 21.6.0, 20.11.0, 21.7.0, 21.8.0, 3.2.0

## Installation

```bash
npm install
```

## Usage

### Basic scan (scans user home directory by default):
```bash
./detect-nx-payload.js
# or
node detect-nx-payload.js
```

### Scan specific directories:
```bash
# Scan current directory
./detect-nx-payload.js -p .

# Scan multiple directories
./detect-nx-payload.js -p /path/to/project1 /path/to/project2

# Scan with verbose output
./detect-nx-payload.js -v
```

### Full filesystem scan (requires appropriate permissions):
```bash
# Scan entire filesystem (use with caution, may take long time)
sudo ./detect-nx-payload.js --full-scan
```

### Remove detected malicious artifacts:
```bash
# Scan and remove malicious files
./detect-nx-payload.js --remove

# Remove with verbose output
./detect-nx-payload.js --remove --verbose

# Remove from specific directories
./detect-nx-payload.js --remove -p /path/to/project
```

### Using npm scripts:
```bash
npm run detect    # Scan only (home directory)
npm run clean     # Scan and remove
```

## What it detects

1. **Inventory Files**: `/tmp/inventory.txt` and backup files containing harvested data
2. **Modified Shell Configs**: Malicious shutdown commands in .bashrc, .zshrc, etc.
3. **Malicious telemetry.js**: Files containing the payload code
4. **Compromised Packages**: NX packages with affected versions
5. **Suspicious Repositories**: GitHub repos created by the malware
6. **Malicious postinstall scripts**: Package.json files with payload execution

## Detection Process

The script performs a comprehensive scan:
- Checks temporary directories for inventory files
- Examines shell configuration files for injected shutdown commands
- Scans node_modules directories for malicious telemetry.js files
- Identifies compromised package versions
- Searches for suspicious GitHub repository references

## Cleanup Process

When run with `--remove` flag:
- Deletes inventory files from /tmp
- Removes malicious telemetry.js files
- Cleans shutdown commands from shell configs (creates backups)
- Removes suspicious repository directories

## Safety Features

- Creates backups before modifying shell configuration files
- Provides detailed reporting of all findings
- Requires explicit `--remove` flag for destructive operations
- Shows preview of file contents before removal

## System Requirements

- Node.js 14.0.0 or higher
- Works on macOS, Linux, and Windows
- Requires read permissions for system directories

## Output

The tool provides color-coded output:
- 🔴 RED: Malware detected
- 🟡 YELLOW: Warnings and suspicious patterns
- 🟢 GREEN: Clean system or successful removal
- 🔵 CYAN: Information messages

## License

MIT