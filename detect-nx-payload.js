#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const { program } = require('commander');

const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

// Constants
const SUSPICIOUS_VERSIONS = ['21.5.0', '20.9.0', '20.10.0', '21.6.0', '20.11.0', '21.7.0', '21.8.0', '3.2.0'];
const NX_PACKAGE_PATTERN = /(@nx\/|^nx$|nx@)/;

// Utility functions
function isNxPackage(name) {
    return name === 'nx' || name.startsWith('@nx/') || name.startsWith('@nrwl/');
}

function isSuspiciousVersion(version) {
    return SUSPICIOUS_VERSIONS.includes(version);
}

class NxPayloadDetector {
    constructor(options) {
        this.options = options;
        this.findings = [];
        this.homeDir = os.homedir();
        this.nxPackagesFound = [];
        this.telemetryFiles = [];
        this.osvVulnerabilities = new Map();
    }

    log(message, level = 'info') {
        const prefix = {
            'info': `${CYAN}[INFO]${RESET}`,
            'warn': `${YELLOW}[WARN]${RESET}`,
            'error': `${RED}[ERROR]${RESET}`,
            'success': `${GREEN}[SUCCESS]${RESET}`,
            'found': `${RED}${BOLD}[MALWARE FOUND]${RESET}`
        };
        console.log(`${prefix[level]} ${message}`);
    }

    async checkOSVVulnerability(packageName, version) {
        const cacheKey = `${packageName}@${version}`;
        
        if (this.osvVulnerabilities.has(cacheKey)) {
            return this.osvVulnerabilities.get(cacheKey);
        }

        return new Promise((resolve) => {
            const data = JSON.stringify({
                version: version,
                package: {
                    name: packageName,
                    ecosystem: 'npm'
                }
            });

            const options = {
                hostname: 'api.osv.dev',
                port: 443,
                path: '/v1/query',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': data.length
                },
                timeout: 5000
            };

            const req = https.request(options, (res) => {
                let body = '';

                res.on('data', (chunk) => {
                    body += chunk;
                });

                res.on('end', () => {
                    try {
                        const result = JSON.parse(body);
                        const vulns = result.vulns || [];
                        
                        const hasNxCompromise = vulns.some(vuln => {
                            const summary = (vuln.summary || '').toLowerCase();
                            const details = (vuln.details || '').toLowerCase();
                            const aliases = vuln.aliases || [];
                            
                            return summary.includes('malicious') || 
                                   summary.includes('compromised') ||
                                   summary.includes('backdoor') ||
                                   details.includes('malicious') ||
                                   details.includes('compromised') ||
                                   aliases.some(a => a.includes('MAL-'));
                        });
                        
                        const result_data = {
                            hasVulnerabilities: vulns.length > 0,
                            hasNxCompromise: hasNxCompromise,
                            vulnerabilityCount: vulns.length,
                            vulnerabilities: vulns.map(v => ({
                                id: v.id,
                                summary: v.summary,
                                severity: v.severity,
                                aliases: v.aliases || []
                            }))
                        };
                        
                        this.osvVulnerabilities.set(cacheKey, result_data);
                        resolve(result_data);
                    } catch (err) {
                        this.osvVulnerabilities.set(cacheKey, null);
                        resolve(null);
                    }
                });
            });

            req.on('error', () => {
                this.osvVulnerabilities.set(cacheKey, null);
                resolve(null);
            });

            req.on('timeout', () => {
                req.destroy();
                this.osvVulnerabilities.set(cacheKey, null);
                resolve(null);
            });

            req.write(data);
            req.end();
        });
    }

    async checkAllVulnerabilities() {
        const uniquePackages = new Map();
        for (const pkg of this.nxPackagesFound) {
            if (isNxPackage(pkg.name)) {
                const key = `${pkg.name}@${pkg.version}`;
                if (!uniquePackages.has(key)) {
                    uniquePackages.set(key, pkg);
                }
            }
        }
        
        if (uniquePackages.size === 0) {
            return;
        }
        
        let packagesToCheck = Array.from(uniquePackages.values());
        this.log(`Checking ${uniquePackages.size} unique NX package(s) for vulnerabilities via OSV database...`);
        
        if (this.options.verbose && packagesToCheck.length <= 10) {
            for (const pkg of packagesToCheck) {
                this.log(`  Checking: ${pkg.name}@${pkg.version}`, 'info');
            }
        } else if (this.options.verbose) {
            this.log(`  Checking ${packagesToCheck.length} packages (use --skip-osv to skip this check)`, 'info');
        }
        
        const BATCH_SIZE = 100;
        const results = [];
        const totalBatches = Math.ceil(packagesToCheck.length / BATCH_SIZE);
        
        if (totalBatches > 1) {
            this.log(`Processing in ${totalBatches} batches of up to ${BATCH_SIZE} packages each...`);
        }
        
        for (let i = 0; i < packagesToCheck.length; i += BATCH_SIZE) {
            const batch = packagesToCheck.slice(i, Math.min(i + BATCH_SIZE, packagesToCheck.length));
            const currentBatch = Math.floor(i/BATCH_SIZE) + 1;
            
            if (totalBatches > 1) {
                this.log(`  Checking batch ${currentBatch}/${totalBatches} (${batch.length} packages)...`, 'info');
            }
            
            const batchPromises = batch.map(pkg => 
                this.checkOSVVulnerability(pkg.name, pkg.version)
                    .then(result => ({ ...pkg, osvResult: result }))
            );
            
            const batchResults = await Promise.all(batchPromises);
            results.push(...batchResults);
            
            if (i + BATCH_SIZE < packagesToCheck.length) {
                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }
        
        let osvConfirmedCount = 0;
        let osvVulnerableCount = 0;
        
        for (const result of results) {
            if (result.osvResult && result.osvResult.hasNxCompromise) {
                osvConfirmedCount++;
                for (const pkg of this.nxPackagesFound) {
                    if (pkg.name === result.name && pkg.version === result.version) {
                        pkg.suspicious = true;
                        pkg.osvVerified = true;
                        pkg.osvVulnerabilities = result.osvResult.vulnerabilities;
                    }
                }
                
                this.log(`OSV confirmed compromised: ${result.name}@${result.version}`, 'found');
            } else if (result.osvResult && result.osvResult.hasVulnerabilities) {
                osvVulnerableCount++;
                if (this.options.verbose) {
                    this.log(`OSV found vulnerabilities in ${result.name}@${result.version} (${result.osvResult.vulnerabilityCount} issues)`, 'warn');
                }
            } else if (this.options.verbose && packagesToCheck.length <= 10) {
                this.log(`OSV check clean: ${result.name}@${result.version}`, 'success');
            }
        }
        
        if (osvConfirmedCount > 0) {
            this.log(`OSV confirmed ${osvConfirmedCount} compromised package(s)`, 'warn');
        }
        if (osvVulnerableCount > 0 && this.options.verbose) {
            this.log(`OSV found ${osvVulnerableCount} package(s) with other vulnerabilities`, 'warn');
        }
    }

    // Check for malicious inventory files
    checkInventoryFiles() {
        this.log('Checking for inventory files...');
        const inventoryFiles = [
            '/tmp/inventory.txt',
            '/tmp/inventory.txt.bak',
            path.join(os.tmpdir(), 'inventory.txt'),
            path.join(os.tmpdir(), 'inventory.txt.bak')
        ];

        for (const file of inventoryFiles) {
            if (fs.existsSync(file)) {
                const stats = fs.statSync(file);
                const content = fs.readFileSync(file, 'utf-8').substring(0, 500);
                this.findings.push({
                    type: 'inventory_file',
                    path: file,
                    size: stats.size,
                    modified: stats.mtime,
                    preview: content
                });
                this.log(`Found suspicious inventory file: ${file}`, 'found');
            }
        }
    }

    // Check shell configuration files for malicious shutdown commands
    checkShellConfigs() {
        this.log('Checking shell configuration files...');
        const shellConfigs = [
            '.bashrc',
            '.bash_profile',
            '.zshrc',
            '.profile',
            '.config/fish/config.fish'
        ];

        for (const config of shellConfigs) {
            const configPath = path.join(this.homeDir, config);
            if (fs.existsSync(configPath)) {
                try {
                    const content = fs.readFileSync(configPath, 'utf-8');
                    if (content.includes('sudo shutdown') || content.includes('shutdown -h')) {
                        this.findings.push({
                            type: 'shell_config_modified',
                            path: configPath,
                            pattern: 'shutdown command found'
                        });
                        this.log(`Suspicious shutdown command found in: ${configPath}`, 'found');
                    }
                } catch (err) {
                    this.log(`Cannot read ${configPath}: ${err.message}`, 'warn');
                }
            }
        }
    }

    // Check package.json and lock files for NX packages
    checkProjectFiles(dir) {
        const packageJsonPath = path.join(dir, 'package.json');
        const packageLockPath = path.join(dir, 'package-lock.json');
        const yarnLockPath = path.join(dir, 'yarn.lock');
        
        // Check package.json
        if (fs.existsSync(packageJsonPath)) {
            try {
                const pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
                const allDeps = {
                    ...pkgJson.dependencies,
                    ...pkgJson.devDependencies,
                    ...pkgJson.peerDependencies
                };
                
                for (const [name, version] of Object.entries(allDeps || {})) {
                    // Only check NX packages (nx, @nx/*, @nrwl/*)
                    if (isNxPackage(name)) {
                        const cleanVersion = version.replace(/^[\^~]/, '');
                        const suspicious = isSuspiciousVersion(cleanVersion);
                        
                        this.nxPackagesFound.push({
                            name,
                            version: cleanVersion,
                            source: 'package.json',
                            path: packageJsonPath,
                            suspicious
                        });
                        
                        if (suspicious) {
                            this.log(`SUSPICIOUS NX package in ${packageJsonPath}: ${name}@${cleanVersion} (compromised version)`, 'found');
                        }
                    }
                }
            } catch (err) {
                // Ignore parse errors
            }
        }
        
        // Check package-lock.json
        if (fs.existsSync(packageLockPath)) {
            try {
                const lockJson = JSON.parse(fs.readFileSync(packageLockPath, 'utf-8'));
                
                // npm v7+ format
                if (lockJson.packages) {
                    for (const [pkgPath, pkg] of Object.entries(lockJson.packages)) {
                        // Extract the actual package name from the path
                        // Examples: 
                        // "node_modules/nx" -> "nx"
                        // "node_modules/@nx/js" -> "@nx/js"
                        // "node_modules/@nrwl/js/node_modules/nx" -> "nx" (nested)
                        
                        let packageName = '';
                        let fullPath = pkgPath;
                        
                        if (pkgPath.includes('node_modules/')) {
                            // Get the last package name in the path for nested dependencies
                            const parts = pkgPath.split('node_modules/');
                            packageName = parts[parts.length - 1];
                        } else {
                            packageName = pkgPath;
                        }
                        
                        // Check if this is an NX-related package
                        if (isNxPackage(packageName) && pkg.version) {
                            // Only check for suspicious versions if it's actually an NX package
                            const suspicious = isSuspiciousVersion(pkg.version);
                            
                            this.nxPackagesFound.push({
                                name: packageName || pkgPath,
                                version: pkg.version,
                                source: 'package-lock.json',
                                path: packageLockPath,
                                fullPath: fullPath,
                                suspicious
                            });
                            
                            if (suspicious) {
                                const displayPath = fullPath === packageName ? packageName : `${fullPath} (${packageName})`;
                                this.log(`SUSPICIOUS NX package in ${packageLockPath}: ${displayPath}@${pkg.version} (compromised version)`, 'found');
                            } else if (this.options.verbose) {
                                const displayPath = fullPath === packageName ? packageName : `${fullPath} (${packageName})`;
                                this.log(`Found NX package in lock file: ${displayPath}@${pkg.version}`, 'info');
                            }
                        }
                    }
                }
                
                // npm v6 format
                if (lockJson.dependencies) {
                    for (const [name, pkg] of Object.entries(lockJson.dependencies)) {
                        if (NX_PACKAGE_PATTERN.test(name) && pkg.version) {
                            const suspicious = isSuspiciousVersion(pkg.version);
                            
                            this.nxPackagesFound.push({
                                name,
                                version: pkg.version,
                                source: 'package-lock.json (v6)',
                                path: packageLockPath,
                                suspicious
                            });
                            
                            if (suspicious) {
                                this.log(`SUSPICIOUS NX package in ${packageLockPath}: ${name}@${pkg.version} (compromised version)`, 'found');
                            }
                        }
                    }
                }
            } catch (err) {
                // Ignore parse errors
            }
        }
        
        // Check yarn.lock (basic parsing)
        if (fs.existsSync(yarnLockPath)) {
            try {
                const yarnContent = fs.readFileSync(yarnLockPath, 'utf-8');
                const lines = yarnContent.split('\n');
                
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i];
                    if (NX_PACKAGE_PATTERN.test(line) && line.includes('@')) {
                        // Look for version line
                        for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
                            if (lines[j].includes('version')) {
                                const versionMatch = lines[j].match(/version\s+"([^"]+)"/);
                                if (versionMatch) {
                                    const pkgMatch = line.match(/([@\w/-]+)@/);
                                    if (pkgMatch) {
                                        const name = pkgMatch[1];
                                        const version = versionMatch[1];
                                        const suspicious = isSuspiciousVersion(version);
                                        
                                        this.nxPackagesFound.push({
                                            name,
                                            version,
                                            source: 'yarn.lock',
                                            path: yarnLockPath,
                                            suspicious
                                        });
                                        
                                        if (suspicious) {
                                            this.log(`SUSPICIOUS NX package in ${yarnLockPath}: ${name}@${version} (compromised version)`, 'found');
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (err) {
                // Ignore read errors
            }
        }
    }

    // Check for malicious telemetry.js files in node_modules
    checkNodeModules() {
        this.log('Scanning for malicious telemetry.js files...');
        
        // Determine search directories based on options
        let searchDirs;
        
        if (this.options.fullScan) {
            // Full filesystem scan
            searchDirs = ['/'];
            this.log('WARNING: Full filesystem scan enabled. This may take a long time.', 'warn');
        } else if (this.options.paths) {
            // Use custom paths provided by user exactly as given
            searchDirs = this.options.paths;
            if (searchDirs.includes('/')) {
                this.log('WARNING: Searching from root directory. This may take a long time.', 'warn');
            }
        } else {
            // Default to user home directory
            searchDirs = [this.homeDir];
        }
        
        this.log(`Searching recursively in ${searchDirs.length} ${searchDirs.length === 1 ? 'directory' : 'directories'}`);
        if (this.options.verbose) {
            searchDirs.forEach(dir => this.log(`  • ${dir}`, 'info'));
        }

        for (const dir of searchDirs) {
            if (fs.existsSync(dir)) {
                if (this.options.verbose) {
                    this.log(`Scanning: ${dir}`);
                }
                this.scanDirectoryForPayload(dir);
            }
        }
    }

    scanDirectoryForPayload(startDir) {
        const maxDepth = this.options.fullScan ? 8 : 5;
        const visited = new Set();
        
        // Directories to skip during scanning
        const skipDirs = new Set([
            'node_modules/.cache',
            'node_modules/.vite',
            '.git',
            '.svn',
            '.hg',
            'Library',
            'System',
            'private',
            'proc',
            'dev',
            'sys'
        ]);

        const scan = (dir, depth = 0) => {
            if (depth > maxDepth || visited.has(dir)) return;
            visited.add(dir);

            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                
                // Check for project files at this level
                if (fs.existsSync(path.join(dir, 'package.json'))) {
                    this.checkProjectFiles(dir);
                }
                
                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);
                    
                    // Skip system directories and symlinks
                    if (skipDirs.has(entry.name)) continue;
                    if (entry.name.startsWith('.') && entry.name !== '.npm' && entry.name !== '.pnpm') continue;
                    if (entry.isSymbolicLink()) continue;
                    
                    if (entry.isDirectory()) {
                        // Check for node_modules with affected packages
                        if (entry.name === 'node_modules') {
                            // Check all NX packages in node_modules
                            this.scanNodeModulesForNx(fullPath);
                        } else if (depth < maxDepth) {
                            scan(fullPath, depth + 1);
                        }
                    } else if (entry.name === 'telemetry.js' || entry.name === 'telemetry.ts') {
                        // Check any telemetry file
                        this.telemetryFiles.push(fullPath);
                        this.analyzeTelemetryFile(fullPath);
                    }
                }
            } catch (err) {
                // Silently skip directories we can't read
            }
        };

        scan(startDir);
    }
    
    scanNodeModulesForNx(nodeModulesPath) {
        try {
            const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
            
            for (const entry of entries) {
                if (entry.isDirectory()) {
                    const fullPath = path.join(nodeModulesPath, entry.name);
                    
                    // Check @nx scoped packages
                    if (entry.name === '@nx') {
                        const nxEntries = fs.readdirSync(fullPath, { withFileTypes: true });
                        for (const nxEntry of nxEntries) {
                            if (nxEntry.isDirectory()) {
                                const pkgPath = path.join(fullPath, nxEntry.name);
                                this.checkPackageForTelemetry(pkgPath, `@nx/${nxEntry.name}`);
                                this.checkInstalledPackageVersion(pkgPath, `@nx/${nxEntry.name}`);
                            }
                        }
                    }
                    // Check nx package
                    else if (entry.name === 'nx') {
                        this.checkPackageForTelemetry(fullPath, 'nx');
                        this.checkInstalledPackageVersion(fullPath, 'nx');
                    }
                    // Check any package that starts with nx-
                    else if (entry.name.startsWith('nx-')) {
                        this.checkPackageForTelemetry(fullPath, entry.name);
                        this.checkInstalledPackageVersion(fullPath, entry.name);
                    }
                }
            }
        } catch (err) {
            // Silently skip
        }
    }
    
    checkInstalledPackageVersion(pkgPath, pkgName) {
        const packageJsonPath = path.join(pkgPath, 'package.json');
        
        if (fs.existsSync(packageJsonPath)) {
            try {
                const pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
                const suspicious = isSuspiciousVersion(pkgJson.version);
                
                this.nxPackagesFound.push({
                    name: pkgName,
                    version: pkgJson.version,
                    source: 'node_modules',
                    path: pkgPath,
                    suspicious
                });
                
                if (suspicious) {
                    this.log(`SUSPICIOUS installed NX package at ${pkgPath}: ${pkgName}@${pkgJson.version} (compromised version)`, 'found');
                } else if (this.options.verbose) {
                    this.log(`Found NX package: ${pkgName}@${pkgJson.version}`, 'info');
                }
            } catch (err) {
                // Ignore parse errors
            }
        }
    }

    checkPackageForTelemetry(pkgPath, pkgName) {
        const telemetryPath = path.join(pkgPath, 'telemetry.js');
        const packageJsonPath = path.join(pkgPath, 'package.json');

        // Check for telemetry.js
        if (fs.existsSync(telemetryPath)) {
            this.analyzeTelemetryFile(telemetryPath);
        }

        // Check package.json for suspicious postinstall
        if (fs.existsSync(packageJsonPath)) {
            try {
                const pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
                
                if (isSuspiciousVersion(pkgJson.version)) {
                    this.findings.push({
                        type: 'suspicious_package_version',
                        path: packageJsonPath,
                        package: pkgName,
                        version: pkgJson.version
                    });
                    this.log(`SUSPICIOUS package at ${pkgPath}: ${pkgName}@${pkgJson.version} (compromised version)`, 'found');
                }

                if (pkgJson.scripts?.postinstall?.includes('telemetry.js')) {
                    this.findings.push({
                        type: 'malicious_postinstall',
                        path: packageJsonPath,
                        script: pkgJson.scripts.postinstall
                    });
                    this.log(`Malicious postinstall script found in: ${packageJsonPath}`, 'found');
                }
            } catch (err) {
                // Ignore parse errors
            }
        }
    }

    analyzeTelemetryFile(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const suspiciousPatterns = [
                'inventory.txt',
                's1ngularity-repository',
                'wallet',
                'keyfile',
                'GH_TOKEN',
                'NPM_TOKEN',
                'sudo shutdown',
                'execSync',
                'github.com/settings/tokens'
            ];

            const foundPatterns = suspiciousPatterns.filter(pattern => 
                content.toLowerCase().includes(pattern.toLowerCase())
            );

            if (foundPatterns.length > 0) {
                this.findings.push({
                    type: 'malicious_telemetry',
                    path: filePath,
                    patterns: foundPatterns,
                    size: fs.statSync(filePath).size
                });
                this.log(`Malicious telemetry.js found: ${filePath}`, 'found');
                this.log(`  Suspicious patterns: ${foundPatterns.join(', ')}`, 'warn');
            }
        } catch (err) {
            // Ignore read errors
        }
    }

    // Check for suspicious GitHub repositories
    checkGitHubRepos() {
        this.log('Checking for suspicious GitHub repositories...');
        
        try {
            // Check git config for suspicious repos
            const gitConfig = path.join(this.homeDir, '.gitconfig');
            if (fs.existsSync(gitConfig)) {
                const content = fs.readFileSync(gitConfig, 'utf-8');
                if (content.includes('s1ngularity-repository')) {
                    this.findings.push({
                        type: 'git_config_modified',
                        path: gitConfig,
                        pattern: 's1ngularity-repository'
                    });
                    this.log('Suspicious repository reference found in git config', 'found');
                }
            }

            // Check for local repos with suspicious names
            const suspiciousRepoPattern = /s1ngularity-repository/i;
            const gitDirs = [
                path.join(this.homeDir, 'repos'),
                path.join(this.homeDir, 'projects'),
                path.join(this.homeDir, 'code'),
                path.join(this.homeDir, 'dev'),
                path.join(this.homeDir, 'Documents'),
                '/tmp'
            ];

            for (const dir of gitDirs) {
                if (fs.existsSync(dir)) {
                    try {
                        const entries = fs.readdirSync(dir);
                        for (const entry of entries) {
                            if (suspiciousRepoPattern.test(entry)) {
                                const fullPath = path.join(dir, entry);
                                this.findings.push({
                                    type: 'suspicious_repo',
                                    path: fullPath
                                });
                                this.log(`Suspicious repository found: ${fullPath}`, 'found');
                            }
                        }
                    } catch (err) {
                        // Skip directories we can't read
                    }
                }
            }
        } catch (err) {
            this.log(`Error checking GitHub repos: ${err.message}`, 'warn');
        }
    }

    // Clean up malicious artifacts
    cleanup() {
        if (!this.options.remove) {
            this.log('Run with --remove flag to delete malicious files', 'info');
            return;
        }

        this.log('Starting cleanup process...', 'warn');
        let cleaned = 0;

        for (const finding of this.findings) {
            if (finding.type === 'inventory_file' || 
                finding.type === 'malicious_telemetry' || 
                finding.type === 'suspicious_repo') {
                
                try {
                    if (fs.existsSync(finding.path)) {
                        const stats = fs.statSync(finding.path);
                        if (stats.isDirectory()) {
                            fs.rmSync(finding.path, { recursive: true, force: true });
                        } else {
                            fs.unlinkSync(finding.path);
                        }
                        this.log(`Removed: ${finding.path}`, 'success');
                        cleaned++;
                    }
                } catch (err) {
                    this.log(`Failed to remove ${finding.path}: ${err.message}`, 'error');
                }
            } else if (finding.type === 'shell_config_modified') {
                try {
                    let content = fs.readFileSync(finding.path, 'utf-8');
                    // Remove lines containing shutdown commands
                    const lines = content.split('\n');
                    const filteredLines = lines.filter(line => 
                        !line.includes('sudo shutdown') && !line.includes('shutdown -h')
                    );
                    
                    if (lines.length !== filteredLines.length) {
                        // Backup original file
                        fs.copyFileSync(finding.path, `${finding.path}.backup-${Date.now()}`);
                        fs.writeFileSync(finding.path, filteredLines.join('\n'));
                        this.log(`Cleaned shutdown commands from: ${finding.path}`, 'success');
                        this.log(`  Backup saved as: ${finding.path}.backup-*`, 'info');
                        cleaned++;
                    }
                } catch (err) {
                    this.log(`Failed to clean ${finding.path}: ${err.message}`, 'error');
                }
            }
        }

        if (cleaned > 0) {
            this.log(`Cleanup complete. Removed ${cleaned} malicious artifacts.`, 'success');
        }
    }

    // Generate report
    generateReport() {
        console.log('\n' + '='.repeat(60));
        console.log(`${BOLD}NX PAYLOAD DETECTION REPORT${RESET}`);
        console.log('='.repeat(60));
        console.log(`Scan Date: ${new Date().toISOString()}`);
        console.log(`System: ${os.type()} ${os.release()}`);
        console.log(`Home Directory: ${this.homeDir}`);
        console.log('='.repeat(60));
        
        // Report telemetry files found
        if (this.telemetryFiles.length > 0) {
            console.log(`\n${YELLOW}TELEMETRY FILES FOUND:${RESET}`);
            for (const file of this.telemetryFiles) {
                console.log(`  • ${file}`);
            }
        }

        // Report malicious artifacts
        if (this.findings.length === 0) {
            console.log(`\n${GREEN}✓ No malicious artifacts detected${RESET}`);
        } else {
            console.log(`\n${RED}⚠ Found ${this.findings.length} suspicious artifact(s)${RESET}\n`);
            
            // Group findings by type
            const grouped = {};
            for (const finding of this.findings) {
                if (!grouped[finding.type]) {
                    grouped[finding.type] = [];
                }
                grouped[finding.type].push(finding);
            }

            for (const [type, items] of Object.entries(grouped)) {
                console.log(`\n${YELLOW}${type.toUpperCase().replace(/_/g, ' ')}:${RESET}`);
                for (const item of items) {
                    console.log(`  • ${item.path}`);
                    if (item.patterns) {
                        console.log(`    Patterns: ${item.patterns.join(', ')}`);
                    }
                    if (item.version) {
                        console.log(`    Version: ${item.version}`);
                    }
                }
            }
        }

        // Report NX version summary
        if (this.nxPackagesFound.length > 0) {
            console.log('\n' + '='.repeat(60));
            console.log(`${CYAN}${BOLD}NX VERSION SUMMARY${RESET}`);
            console.log('='.repeat(60));
            
            // Get distinct versions for main NX packages
            const versionMap = new Map();
            
            for (const pkg of this.nxPackagesFound) {
                // Focus on main nx package and @nx/* packages
                if (isNxPackage(pkg.name) && !pkg.name.startsWith('@nrwl/')) {
                    if (!versionMap.has(pkg.version)) {
                        versionMap.set(pkg.version, {
                            count: 0,
                            packages: new Set(),
                            suspicious: isSuspiciousVersion(pkg.version)
                        });
                    }
                    versionMap.get(pkg.version).count++;
                    versionMap.get(pkg.version).packages.add(pkg.name);
                }
            }
            
            // Sort versions (newest first)
            const sortedVersions = Array.from(versionMap.entries()).sort((a, b) => {
                // Put suspicious versions first
                if (a[1].suspicious && !b[1].suspicious) return -1;
                if (!a[1].suspicious && b[1].suspicious) return 1;
                // Then sort by version number (simple string comparison)
                return b[0].localeCompare(a[0]);
            });
            
            if (sortedVersions.length > 0) {
                console.log(`\nDistinct NX versions found:`);
                
                // Show suspicious versions first
                const suspiciousVersionsList = sortedVersions.filter(([_, info]) => info.suspicious);
                const cleanVersionsList = sortedVersions.filter(([_, info]) => !info.suspicious);
                
                if (suspiciousVersionsList.length > 0) {
                    console.log(`\n${RED}⚠ COMPROMISED VERSIONS:${RESET}`);
                    for (const [version, info] of suspiciousVersionsList) {
                        const pkgList = Array.from(info.packages).slice(0, 3).join(', ');
                        const morePackages = info.packages.size > 3 ? ` (+${info.packages.size - 3} more)` : '';
                        
                        // Check if this version was verified by OSV
                        const osvVerified = this.nxPackagesFound.some(p => 
                            p.version === version && p.osvVerified
                        );
                        const verifiedText = osvVerified ? ' [OSV confirmed]' : '';
                        
                        console.log(`  ${RED}• ${version} - ${info.count} package(s): ${pkgList}${morePackages}${verifiedText}${RESET}`);
                    }
                }
                
                if (cleanVersionsList.length > 0) {
                    console.log(`\n${GREEN}✓ CLEAN VERSIONS:${RESET}`);
                    for (const [version, info] of cleanVersionsList) {
                        const pkgList = Array.from(info.packages).slice(0, 3).join(', ');
                        const morePackages = info.packages.size > 3 ? ` (+${info.packages.size - 3} more)` : '';
                        console.log(`  • ${version} - ${info.count} package(s): ${pkgList}${morePackages}`);
                    }
                }
            }
        }

        console.log('\n' + '='.repeat(60));
        
        // Summary and recommendations
        const hasSuspicious = this.nxPackagesFound.some(p => p.suspicious);
        const hasMalware = this.findings.length > 0;
        
        if (hasSuspicious || hasMalware) {
            console.log(`\n${RED}${BOLD}⚠ SECURITY ALERT${RESET}`);
            if (hasSuspicious) {
                console.log(`${YELLOW}• Found NX packages with compromised versions${RESET}`);
                console.log(`  Update these packages immediately to safe versions`);
            }
            if (hasMalware) {
                console.log(`${RED}• Found malicious artifacts on your system${RESET}`);
                if (!this.options.remove) {
                    console.log(`\n${YELLOW}To remove malicious artifacts, run:${RESET}`);
                    console.log(`${CYAN}  node detect-nx-payload.js --remove${RESET}`);
                }
            }
        } else if (this.nxPackagesFound.length > 0) {
            console.log(`\n${GREEN}✓ All NX packages appear to be clean versions${RESET}`);
        }
    }

    async run() {
        console.log(`${BOLD}${CYAN}NX Payload Detector v1.0${RESET}`);
        console.log('Starting scan for malicious NX package artifacts...\n');

        try {
            this.checkInventoryFiles();
            this.checkShellConfigs();
            this.checkNodeModules();
            this.checkGitHubRepos();
            
            // Check vulnerabilities via OSV API if we found NX packages
            if (this.nxPackagesFound.length > 0 && !this.options.skipOsv) {
                await this.checkAllVulnerabilities();
            }

            if (this.options.remove && this.findings.length > 0) {
                this.cleanup();
            }

            this.generateReport();
        } catch (err) {
            this.log(`Fatal error: ${err.message}`, 'error');
            process.exit(1);
        }
    }
}

// CLI setup
program
    .name('nx-payload-detector')
    .description('Detect and remove malicious NX package payload artifacts')
    .version('1.0.0')
    .option('-r, --remove', 'Remove detected malicious files')
    .option('-v, --verbose', 'Verbose output')
    .option('-p, --paths <paths...>', 'Custom paths to scan (default: user home directory)')
    .option('-f, --full-scan', 'Scan entire filesystem (use with caution)')
    .option('--skip-osv', 'Skip OSV vulnerability database check')
    .parse(process.argv);

const options = program.opts();
const detector = new NxPayloadDetector(options);
detector.run();