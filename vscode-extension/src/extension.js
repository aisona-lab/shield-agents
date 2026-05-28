/**
 * Shield Agents - VS Code Extension
 * 
 * Provides real-time security scanning powered by Shield Agents.
 * Scans files on save and displays findings as diagnostics.
 */

const vscode = require('vscode');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

// Severity mapping from Shield Agents to VS Code
const SEVERITY_MAP = {
    'CRITICAL': vscode.DiagnosticSeverity.Error,
    'HIGH': vscode.DiagnosticSeverity.Error,
    'MEDIUM': vscode.DiagnosticSeverity.Warning,
    'LOW': vscode.DiagnosticSeverity.Information,
    'INFO': vscode.DiagnosticSeverity.Hint,
};

// Minimum severity filter
const SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

let diagnosticCollection;
let outputChannel;
let lastReport = null;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    outputChannel = vscode.window.createOutputChannel('Shield Agents');
    diagnosticCollection = vscode.languages.createDiagnosticCollection('shield-agents');

    context.subscriptions.push(diagnosticCollection);
    context.subscriptions.push(outputChannel);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('shield-agents.scanFile', scanCurrentFile)
    );
    context.subscriptions.push(
        vscode.commands.registerCommand('shield-agents.scanWorkspace', scanWorkspace)
    );
    context.subscriptions.push(
        vscode.commands.registerCommand('shield-agents.showReport', showReport)
    );
    context.subscriptions.push(
        vscode.commands.registerCommand('shield-agents.clearCache', clearCache)
    );

    // Scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('shieldAgents');
            if (config.get('scanOnSave', true)) {
                scanDocument(document);
            }
        })
    );

    // Scan active file on open
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }

    outputChannel.appendLine('Shield Agents extension activated');
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (outputChannel) {
        outputChannel.dispose();
    }
}

/**
 * Scan the current active file.
 */
async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to scan');
        return;
    }
    await scanDocument(editor.document);
}

/**
 * Scan the entire workspace.
 */
async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    const workspacePath = workspaceFolders[0].uri.fsPath;
    
    vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'Shield Agents: Scanning workspace...',
            cancellable: true,
        },
        async (progress, token) => {
            try {
                const result = await runShieldAgentsCLI(workspacePath, true);
                if (result && result.findings) {
                    applyFindingsToEditors(result.findings);
                    lastReport = result;
                    
                    const critical = result.findings.filter(f => f.severity === 'CRITICAL').length;
                    const high = result.findings.filter(f => f.severity === 'HIGH').length;
                    
                    vscode.window.showInformationMessage(
                        `Shield Agents: Found ${result.findings.length} issues (${critical} critical, ${high} high) - Risk: ${result.risk_score || 'N/A'}/100`
                    );
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Shield Agents scan failed: ${error.message}`);
            }
        }
    );
}

/**
 * Scan a single document.
 * @param {vscode.TextDocument} document
 */
async function scanDocument(document) {
    const config = vscode.workspace.getConfiguration('shieldAgents');
    const minSeverity = config.get('minSeverity', 'LOW');
    const filePath = document.uri.fsPath;

    // Skip non-source files
    const sourceExtensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.rs'];
    if (!sourceExtensions.some(ext => filePath.endsWith(ext))) {
        return;
    }

    try {
        const result = await runShieldAgentsCLI(filePath, false);
        if (result && result.findings) {
            // Filter by minimum severity
            const minIdx = SEVERITY_ORDER.indexOf(minSeverity);
            const filtered = result.findings.filter(f => {
                const fIdx = SEVERITY_ORDER.indexOf(f.severity?.toUpperCase() || 'MEDIUM');
                return fIdx >= minIdx;
            });

            applyDiagnostics(document, filtered);
            lastReport = result;

            // Update status bar
            const critical = filtered.filter(f => f.severity === 'CRITICAL').length;
            const high = filtered.filter(f => f.severity === 'HIGH').length;
            
            if (critical > 0 || high > 0) {
                vscode.window.setStatusBarMessage(
                    `Shield: ${critical} critical, ${high} high`,
                    5000
                );
            }
        }
    } catch (error) {
        outputChannel.appendLine(`Scan error: ${error.message}`);
    }
}

/**
 * Apply diagnostics to a document from findings.
 * @param {vscode.TextDocument} document
 * @param {Array} findings
 */
function applyDiagnostics(document, findings) {
    const diagnostics = [];
    const fileUri = document.uri.fsPath;

    for (const finding of findings) {
        // Only show findings for the current file
        if (finding.file && !fileUri.endsWith(finding.file.replace(/^.*[\/\\]/, ''))) {
            continue;
        }

        const line = (finding.line || 1) - 1; // VS Code uses 0-based lines
        const range = new vscode.Range(
            Math.max(0, line),
            0,
            Math.max(0, line),
            Math.max(1, (finding.code_snippet || '').length)
        );

        const severity = SEVERITY_MAP[finding.severity?.toUpperCase()] || vscode.DiagnosticSeverity.Warning;
        
        const diagnostic = new vscode.Diagnostic(
            range,
            `[Shield Agents] ${finding.title || 'Security Issue'}: ${finding.description || ''}`,
            severity
        );

        diagnostic.source = 'Shield Agents';
        diagnostic.code = finding.rule_id || finding.cwe || '';
        
        if (finding.remediation) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `Fix: ${finding.remediation}`
                )
            ];
        }

        diagnostics.push(diagnostic);
    }

    diagnosticCollection.set(document.uri, diagnostics);
}

/**
 * Apply findings to all open editors.
 * @param {Array} findings
 */
function applyFindingsToEditors(findings) {
    vscode.window.visibleTextEditors.forEach(editor => {
        applyDiagnostics(editor.document, findings);
    });
}

/**
 * Run the Shield Agents CLI.
 * @param {string} targetPath - Path to scan
 * @param {boolean} isWorkspace - Whether scanning a workspace
 * @returns {Promise<Object>} Scan results
 */
function runShieldAgentsCLI(targetPath, isWorkspace = false) {
    return new Promise((resolve, reject) => {
        const config = vscode.workspace.getConfiguration('shieldAgents');
        
        // Build command arguments
        const args = [
            '-m', 'shield_agents.cli',
            'scan', targetPath,
            '--provider', config.get('provider', 'mock'),
            '--no-report',  // We don't need file reports from extension
        ];

        if (!config.get('enableSAST', true)) {
            // Skip SAST if disabled
        }
        if (!config.get('enableSecrets', true)) {
            // Skip secrets if disabled
        }

        // Set environment
        const env = { ...process.env };
        const apiKey = config.get('apiKey', '');
        if (apiKey) {
            env.SHIELD_LLM_API_KEY = apiKey;
        }

        const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

        execFile(pythonCmd, args, {
            cwd: targetPath,
            env: env,
            timeout: 60000,
            maxBuffer: 10 * 1024 * 1024,
        }, (error, stdout, stderr) => {
            if (error && error.code !== 1) {
                // Code 1 means findings found (not an error)
                reject(new Error(stderr || error.message));
                return;
            }

            try {
                // Try to parse JSON from stdout
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseError) {
                // If can't parse JSON, try to find JSON in output
                const jsonMatch = stdout.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    try {
                        resolve(JSON.parse(jsonMatch[0]));
                    } catch {
                        resolve({ findings: [], risk_score: 0 });
                    }
                } else {
                    resolve({ findings: [], risk_score: 0 });
                }
            }
        });
    });
}

/**
 * Show the last generated report.
 */
function showReport() {
    if (!lastReport) {
        vscode.window.showInformationMessage('No report available. Run a scan first.');
        return;
    }

    const panel = vscode.window.createWebviewPanel(
        'shieldAgentsReport',
        'Shield Agents Report',
        vscode.ViewColumn.Two,
        {}
    );

    panel.webview.html = generateReportHtml(lastReport);
}

/**
 * Clear the Shield Agents cache.
 */
async function clearCache() {
    const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
    execFile(pythonCmd, ['-m', 'shield_agents.cli', 'cache', '--clear'], (error) => {
        if (error) {
            vscode.window.showErrorMessage('Failed to clear cache');
        } else {
            vscode.window.showInformationMessage('Shield Agents cache cleared');
        }
    });
}

/**
 * Generate HTML report for webview.
 */
function generateReportHtml(report) {
    const findings = report.findings || [];
    const riskScore = report.risk_score || 0;
    
    let findingsHtml = findings.map((f, i) => `
        <tr>
            <td class="sev-${(f.severity || 'MEDIUM').toLowerCase()}">${f.severity || 'MEDIUM'}</td>
            <td>${f.title || 'Unknown'}</td>
            <td>${f.file || 'N/A'}</td>
            <td>${f.line || 'N/A'}</td>
            <td>${f.remediation || ''}</td>
        </tr>
    `).join('');

    return `<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
        h1 { color: #569cd6; }
        .risk { font-size: 48px; font-weight: bold; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #264f78; padding: 8px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #333; }
        .sev-critical { color: #f44747; font-weight: bold; }
        .sev-high { color: #ff6b6b; }
        .sev-medium { color: #dcdcaa; }
        .sev-low { color: #4ec9b0; }
        .sev-info { color: #6a9955; }
    </style>
</head>
<body>
    <h1>Shield Agents Report</h1>
    <div class="risk" style="color: ${riskScore >= 75 ? '#f44747' : riskScore >= 50 ? '#dcdcaa' : '#4ec9b0'}">
        ${riskScore}/100
    </div>
    <p style="text-align: center">${findings.length} findings</p>
    <table>
        <tr><th>Severity</th><th>Title</th><th>File</th><th>Line</th><th>Remediation</th></tr>
        ${findingsHtml}
    </table>
</body>
</html>`;
}

module.exports = { activate, deactivate };
