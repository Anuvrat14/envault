const { app, BrowserWindow, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

const PORT = 7331;
let flaskProcess = null;
let mainWindow   = null;

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

    flaskProcess.stdout.on('data', d => console.log('[flask]', d.toString().trim()));
    flaskProcess.stderr.on('data', d => console.error('[flask]', d.toString().trim()));
    flaskProcess.on('exit', code => console.log('[flask] exited with code', code));
}

// ── Poll until Flask is ready, then open window ────────────────────────────
function waitForFlask(retries = 30) {
    http.get(`http://127.0.0.1:${PORT}/`, res => {
        createWindow();
    }).on('error', () => {
        if (retries > 0) setTimeout(() => waitForFlask(retries - 1), 500);
        else console.error('Flask failed to start.');
    });
}

// ── Create BrowserWindow ───────────────────────────────────────────────────
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 720,
        minWidth: 800,
        minHeight: 540,
        transparent: true,
        backgroundColor: '#00000000',
        vibrancy: 'under-window',
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

    // Open external links in browser, not Electron
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });

    mainWindow.on('closed', () => { mainWindow = null; });
}

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
