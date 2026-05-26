const { app, BrowserWindow, shell, Notification, dialog, ipcMain } = require('electron');
const { autoUpdater } = require('electron-updater');
const { spawn } = require('child_process');
const path  = require('path');
const http  = require('http');
const log   = require('electron-log');

const PORT = 7331;
let flaskProcess  = null;
let mainWindow    = null;
let loadingWindow = null;

// ── Logging ────────────────────────────────────────────────────────────────
log.transports.file.level = 'info';
autoUpdater.logger = log;
autoUpdater.autoDownload    = true;   // download silently in background
autoUpdater.autoInstallOnAppQuit = true; // install on next quit

// ── Start Flask ────────────────────────────────────────────────────────────
function startFlask() {
    const isPackaged = app.isPackaged;
    const isWin      = process.platform === 'win32';
    const serverBin  = isWin ? 'dotward-server.exe' : 'dotward-server';
    const pythonExe  = isPackaged
        ? path.join(process.resourcesPath, serverBin)
        : (isWin
            ? path.join(__dirname, 'venv', 'Scripts', 'python.exe')
            : path.join(__dirname, 'venv', 'bin', 'python3'));

    const args = isPackaged ? [] : [path.join(__dirname, 'run.py')];

    flaskProcess = spawn(pythonExe, args, {
        cwd: isPackaged ? process.resourcesPath : __dirname,
        env: { ...process.env },
    });

    flaskProcess.stdout.on('data', d => log.info('[flask]', d.toString().trim()));
    flaskProcess.stderr.on('data', d => log.warn('[flask]', d.toString().trim()));
    flaskProcess.on('exit', code => log.info('[flask] exited with code', code));
}

// ── Loading splash (shown while Flask warms up) ────────────────────────────
function createLoadingWindow() {
    const isMac = process.platform === 'darwin';
    loadingWindow = new BrowserWindow({
        width: 340,
        height: 200,
        resizable: false,
        frame: false,
        transparent: isMac,
        alwaysOnTop: true,
        ...(isMac ? {
            vibrancy: 'fullscreen-ui',
            visualEffectState: 'active',
        } : {}),
        backgroundColor: isMac ? '#00000000' : '#0d0d0d',
        webPreferences: { nodeIntegration: false, contextIsolation: true },
        icon: path.join(__dirname, 'static', 'icon.png'),
        show: false,
    });

    const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    height: 200px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    color: #e2e8f0;
    background: transparent;
    -webkit-app-region: drag;
    user-select: none;
  }
  .logo { font-size: 28px; font-weight: 700; letter-spacing: -1px; }
  .logo span { color: #818cf8; }
  .spinner {
    width: 24px; height: 24px;
    border: 2px solid rgba(129,140,248,0.25);
    border-top-color: #818cf8;
    border-radius: 50%;
    animation: spin 0.75s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .label { font-size: 12px; color: #64748b; }
</style>
</head>
<body>
  <div class="logo">dot<span>ward</span></div>
  <div class="spinner"></div>
  <div class="label">Starting up…</div>
</body>
</html>`;

    loadingWindow.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    loadingWindow.once('ready-to-show', () => loadingWindow && loadingWindow.show());
    loadingWindow.on('closed', () => { loadingWindow = null; });
}

// ── Poll until Flask is ready, then open window ────────────────────────────
function waitForFlask(retries = 60) {
    http.get(`http://127.0.0.1:${PORT}/`, () => {
        // Flask is up — close splash and open main window
        if (loadingWindow && !loadingWindow.isDestroyed()) {
            loadingWindow.close();
        }
        if (!mainWindow) createWindow();
    }).on('error', () => {
        if (retries > 0) {
            setTimeout(() => waitForFlask(retries - 1), 500);
        } else {
            log.error('Flask failed to start after 30 seconds.');
            if (loadingWindow && !loadingWindow.isDestroyed()) loadingWindow.close();
            const choice = dialog.showMessageBoxSync({
                type: 'error',
                title: 'Dotward failed to start',
                message: 'The background server didn\'t respond in time.',
                detail: 'This can happen on first launch or on a slow machine. Try restarting the app.',
                buttons: ['Retry', 'Quit'],
                defaultId: 0,
                cancelId: 1,
            });
            if (choice === 0) {
                createLoadingWindow();
                waitForFlask(60);
            } else {
                app.quit();
            }
        }
    });
}

// ── Create BrowserWindow ───────────────────────────────────────────────────
function createWindow() {
    const isMac = process.platform === 'darwin';
    startNotificationPolling();
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 720,
        minWidth: 800,
        minHeight: 540,
        transparent: isMac,
        backgroundColor: isMac ? '#00000000' : '#0d0d0d',
        ...(isMac ? {
            vibrancy: 'fullscreen-ui',
            visualEffectState: 'active',
            titleBarStyle: 'hiddenInset',
            trafficLightPosition: { x: 16, y: 16 },
            frame: false,
        } : {
            frame: true,
            titleBarStyle: 'default',
        }),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
        },
        icon: path.join(__dirname, 'static', 'icon.png'),
    });
    if (isMac) mainWindow.setWindowButtonVisibility(true);
    mainWindow.loadURL(`http://127.0.0.1:${PORT}/`);

    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });

    mainWindow.on('closed', () => { mainWindow = null; });

    // Check for updates 5 seconds after window opens (only in packaged builds)
    if (app.isPackaged) {
        setTimeout(() => checkForUpdates(), 5000);
    }
}

// ── Auto-updater ───────────────────────────────────────────────────────────
function checkForUpdates() {
    autoUpdater.checkForUpdates().catch(err => {
        log.warn('Update check failed:', err.message);
    });
}

autoUpdater.on('checking-for-update', () => {
    log.info('Checking for updates…');
});

autoUpdater.on('update-available', info => {
    log.info('Update available:', info.version);
    // Silent notification — download starts automatically
    if (Notification.isSupported()) {
        new Notification({
            title: 'Dotward Update',
            body: `v${info.version} is downloading in the background.`,
            silent: true,
        }).show();
    }
});

autoUpdater.on('update-not-available', () => {
    log.info('App is up to date.');
});

autoUpdater.on('download-progress', progress => {
    const pct = Math.round(progress.percent);
    if (mainWindow) mainWindow.setProgressBar(pct / 100);
    log.info(`Download progress: ${pct}%`);
});

autoUpdater.on('update-downloaded', info => {
    if (mainWindow) mainWindow.setProgressBar(-1); // clear progress bar
    log.info('Update downloaded:', info.version);

    const response = dialog.showMessageBoxSync(mainWindow, {
        type: 'info',
        title: 'Update Ready',
        message: `Dotward ${info.version} is ready to install.`,
        detail: 'The update will be applied when you restart the app.',
        buttons: ['Restart Now', 'Later'],
        defaultId: 0,
        cancelId: 1,
    });

    if (response === 0) {
        // isSilent=true, isForceRunAfter=true
        // On Windows NSIS this triggers the installer silently then relaunches
        autoUpdater.quitAndInstall(true, true);
    }
});

autoUpdater.on('error', err => {
    log.error('Auto-updater error:', err.message);
});

// ── App lifecycle ──────────────────────────────────────────────────────────
app.whenReady().then(() => {
    startFlask();
    createLoadingWindow();
    waitForFlask();
});

app.on('window-all-closed', () => {
    if (flaskProcess) flaskProcess.kill();
    if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
    if (mainWindow === null && loadingWindow === null) {
        createLoadingWindow();
        waitForFlask();
    } else if (mainWindow) {
        mainWindow.show();
    }
});

app.on('before-quit', () => {
    if (flaskProcess) flaskProcess.kill();
});

// ── Notification polling ───────────────────────────────────────────────────
const _notifiedKeys = new Set();

function startNotificationPolling() {
    setInterval(() => {
        http.get(`http://127.0.0.1:${PORT}/api/notifications/check`, res => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    (data.notifications || []).forEach(n => {
                        const dedupeKey = `${n.type}:${n.project}:${n.key}`;
                        if (_notifiedKeys.has(dedupeKey)) return;
                        _notifiedKeys.add(dedupeKey);
                        setTimeout(() => _notifiedKeys.delete(dedupeKey), 6 * 60 * 60 * 1000);
                        if (Notification.isSupported()) {
                            const icon = n.type === 'expired' || n.type === 'risk' ? '🔴' : '🟡';
                            new Notification({
                                title: `Dotward ${icon}`,
                                body:  n.message,
                                silent: false,
                            }).show();
                        }
                    });
                } catch (_) {}
            });
        }).on('error', () => {});
    }, 60_000);
}
