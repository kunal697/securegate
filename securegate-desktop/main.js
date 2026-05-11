const { app, Tray, Menu, nativeImage, shell, BrowserWindow } = require('electron');
const path = require('path');
const { startSecureGate, stopSecureGate } = require('./src/processManager');
const { enableProxy, disableProxy, trustCertificate } = require('./src/proxyManager');

let tray = null;
let isEnabled = false;
let mainWindow = null;
let isQuitting = false;

function createWindow() {
  if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
    return;
  }

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'SecureGate',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'loading.html'));

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  checkBackendReady();
}

function checkBackendReady() {
  const http = require('http');
  let loaded = false;
  
  const check = () => {
    if (loaded) return;
    const req = http.get('http://localhost:8000/health', (res) => {
      if (res.statusCode === 200) {
        if (mainWindow && !loaded) {
          loaded = true;
          mainWindow.loadURL('http://localhost:8000/dashboard');
        }
      } else {
        setTimeout(check, 2000);
      }
    }).on('error', () => {
      setTimeout(check, 2000);
    });
    // Add timeout to request
    req.on('timeout', () => {
      req.abort();
    });
    req.setTimeout(1000);
  };
  check();
}

app.on('before-quit', () => {
  isQuitting = true;
});

app.on('ready', () => {
  const icon = nativeImage.createEmpty();
  tray = new Tray(icon);
  tray.setTitle('SecureGate');

  updateMenu();
  createWindow();
  
  // Auto-start SecureGate when the app is launched
  handleEnable();
});

// We don't want the app to exit when all windows are closed
app.on('window-all-closed', (e) => {
  e.preventDefault();
});

app.on('will-quit', async () => {
  if (isEnabled) {
    await handleDisable();
  }
});

function updateMenu() {
  const contextMenu = Menu.buildFromTemplate([
    {
      label: isEnabled ? 'Disable SecureGate' : 'Enable SecureGate',
      click: async () => {
        if (isEnabled) {
          await handleDisable();
        } else {
          await handleEnable();
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Open Dashboard',
      click: () => {
        createWindow();
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: async () => {
        isQuitting = true;
        if (isEnabled) {
          await handleDisable();
        }
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);
}

async function handleEnable() {
  if (isEnabled) return;
  console.log('Enabling SecureGate...');

  // 1. Start backend
  startSecureGate();

  // Poll for the certificate file
  const fs = require('fs');
  const os = require('os');
  const certPath = path.join(os.homedir(), '.mitmproxy', 'mitmproxy-ca-cert.pem');
  
  console.log('Waiting for mitmproxy to generate CA certificate...');
  
  const waitForCert = () => {
    return new Promise((resolve) => {
      let attempts = 0;
      const check = () => {
        attempts++;
        if (fs.existsSync(certPath)) {
          resolve(true);
        } else if (attempts > 30) { // 60 seconds timeout
          resolve(false);
        } else {
          setTimeout(check, 2000);
        }
      };
      check();
    });
  };

  const hasCert = await waitForCert();

  if (!hasCert) {
    console.error('Timeout waiting for mitmproxy certificate.');
    return;
  }

  // 2. Trust Cert
  const trusted = await trustCertificate();

  // 3. Set OS Proxy
  if (trusted) {
    await enableProxy();
    isEnabled = true;
    tray.setTitle('SecureGate (Active)');
    updateMenu();
  } else {
    console.error('Failed to trust certificate. Aborting proxy setup.');
  }
}

async function handleDisable() {
  console.log('Disabling SecureGate...');
  // 1. Disable OS Proxy
  await disableProxy();

  // 2. Stop backend
  stopSecureGate();

  isEnabled = false;
  tray.setTitle('SecureGate');
  updateMenu();
}
