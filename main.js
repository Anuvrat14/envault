const { app, BrowserWindow, shell, Notification, dialog, ipcMain } = require('electron');
const { autoUpdater } = require('electron-updater');
const { spawn } = require('child_process');
const path  = require('path');
const http  = require('http');
const log   = require('electron-log');

const PORT = 7331;
let flaskProcess = null;
let mainWindow   = null;

// ── Logging ────────────────────────────────────────────────────────────────
log.transports.file.level = 'info';
autoUpdater.logger = log;
autoUpdater.autoDownload    = true;   // download silently in background
autoUpdater.autoInstallOnAppQuit = true; // install on next quit

// ── Start Flask ────────────────────────────────────────────────────────────
function startFlask() {
    const isPackaged = app.isPackaged;
    const pythonExe  = isPackaged
        ? path.join(process.resourcesPath, 'envault-server')
        : (process.platform === 'win32' ? 'python' : 'python3');

    const args = isPackaged ? [] : [path.join(__dirname, 'run.py')];

    flaskProcess = spawn(pythonExe, args, {
        cwd: isPackaged ? process.resourcesPath : __dirname,
        env: { ...process.env },
    });

    flaskProcess.stdout.on('data', d => log.info('[flask]', d.toString().trim()));
    flaskProcess.stderr.on('data', d => log.warn('[flask]', d.toString().trim()));
    flaskProcess.on('exit', code => log.info('[flask] exited with code', code));
}

// ── Poll until Flask is ready, then open window ────────────────────────────
function waitForFlask(retries = 30) {
    http.get(`http://127.0.0.1:${PORT}/`, () => {
        createWindow();
    }).on('error', () => {
        if (retries > 0) setTimeout(() => waitForFlask(retries - 1), 500);
        else log.error('Flask failed to start.');
    });
}

// ── Create BrowserWindow ───────────────────────────────────────────────────
function createWindow() {
    startNotificationPolling();
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 720,
        minWidth: 800,
        minHeight: 540,
        transparent: true,
        backgroundColor: '#00000000',
        vibrancy: 'fullscreen-ui',
        visualEffectState: 'active',
        titleBarStyle: 'hiddenInset',
        trafficLightPosition: { x: 16, y: 16 },
        frame: false,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
        },
        icon: path.join(__dirname, 'static', 'icon.png'),
    });
    mainWindow.setWindowButtonVisibility(true);
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
            title: 'Envault Update',
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
        message: `Envault ${info.version} is ready to install.`,
        detail: 'The update will be applied when you restart the app.',
        buttons: ['Restart Now', 'Later'],
        defaultId: 0,
        cancelId: 1,
    });

    if (response === 0) {
        autoUpdater.quitAndInstall(false, true);
    }
});

autoUpdater.on('error', err => {
    log.error('Auto-updater error:', err.message);
});

// ── App lifecycle ──────────────────────────────────────────────────────────
app.whenReady().then(() => {
    startFlask();
    waitForFlask();
});

app.on('window-all-closed', () => {
    if (flaskProcess) flaskProcess.kill();
    if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
    if (mainWindow === null) waitForFlask();
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
                                title: `Envault ${icon}`,
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
