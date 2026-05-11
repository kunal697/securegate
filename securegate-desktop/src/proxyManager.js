const { exec } = require('child_process');
const util = require('util');
if (!util.isObject) {
  util.isObject = function(val) {
    return val !== null && typeof val === 'object' && !Array.isArray(val);
  };
}
if (!util.isFunction) {
  util.isFunction = function(val) {
    return typeof val === 'function';
  };
}
if (!util.isString) {
  util.isString = function(val) {
    return typeof val === 'string';
  };
}
const sudo = require('sudo-prompt');
const path = require('path');
const os = require('os');
const fs = require('fs');

const PROXY_PORT = 8080;
const PROXY_HOST = '127.0.0.1';
const MAC_SERVICES = ['Wi-Fi', 'Ethernet'];

const options = {
  name: 'SecureGate',
};

function runSudoCmd(cmd) {
  return new Promise((resolve, reject) => {
    sudo.exec(cmd, options, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

function runCmd(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

async function enableProxy() {
  if (os.platform() === 'darwin') {
    console.log('Enabling macOS proxy...');
    for (const service of MAC_SERVICES) {
      try {
        await runCmd(`networksetup -setwebproxy "${service}" ${PROXY_HOST} ${PROXY_PORT}`);
        await runCmd(`networksetup -setsecurewebproxy "${service}" ${PROXY_HOST} ${PROXY_PORT}`);
        console.log(`Enabled proxy on ${service}`);
      } catch (e) {
        // Service might not exist, ignore
      }
    }
  } else if (os.platform() === 'win32') {
    console.log('Windows proxy configuration not yet fully implemented.');
    // TODO: implement reg add commands
  }
}

async function disableProxy() {
  if (os.platform() === 'darwin') {
    console.log('Disabling macOS proxy...');
    for (const service of MAC_SERVICES) {
      try {
        await runCmd(`networksetup -setwebproxystate "${service}" off`);
        await runCmd(`networksetup -setsecurewebproxystate "${service}" off`);
        console.log(`Disabled proxy on ${service}`);
      } catch (e) {
        // Service might not exist, ignore
      }
    }
  }
}

async function trustCertificate() {
  if (os.platform() === 'darwin') {
    const certPath = path.join(os.homedir(), '.mitmproxy', 'mitmproxy-ca-cert.pem');
    if (!fs.existsSync(certPath)) {
      console.log('Certificate not found at', certPath);
      return false; // Cert might not be generated yet
    }
    
    console.log('Trusting mitmproxy certificate...');
    try {
      const keychainPath = path.join(os.homedir(), 'Library', 'Keychains', 'login.keychain-db');
      const cmd = `security add-trusted-cert -d -r trustRoot -k "${keychainPath}" "${certPath}"`;
      await runCmd(cmd);
      console.log('Certificate trusted successfully.');
      return true;
    } catch (e) {
      console.error('Failed to trust cert:', e);
      return false;
    }
  }
  return true;
}

module.exports = {
  enableProxy,
  disableProxy,
  trustCertificate
};
