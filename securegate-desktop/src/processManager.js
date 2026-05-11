const { spawn } = require('child_process');
const path = require('path');

let securegateProcess = null;

function startSecureGate(onData, onError) {
  if (securegateProcess) {
    console.log('SecureGate is already running.');
    return;
  }

  const isPackaged = __dirname.includes('app.asar');
  
  let scriptPath;
  let cwdPath;
  
  if (isPackaged) {
    const unpackedDir = __dirname.replace('app.asar', 'app.asar.unpacked');
    scriptPath = path.join(unpackedDir, '..', 'backend', 'launch_packaged.sh');
    cwdPath = path.join(unpackedDir, '..', 'backend');
  } else {
    scriptPath = path.join(__dirname, '..', 'backend', 'launch_packaged.sh');
    cwdPath = path.join(__dirname, '..', 'backend');
  }

  console.log(`Starting SecureGate backend from ${scriptPath}`);

  securegateProcess = spawn('bash', [scriptPath], {
    cwd: cwdPath,
    env: { ...process.env }
  });

  securegateProcess.stdout.on('data', (data) => {
    const str = data.toString();
    console.log(`[SecureGate] ${str.trim()}`);
    if (onData) onData(str);
  });

  securegateProcess.stderr.on('data', (data) => {
    const str = data.toString();
    console.error(`[SecureGate ERR] ${str.trim()}`);
    if (onError) onError(str);
  });

  securegateProcess.on('close', (code) => {
    console.log(`SecureGate process exited with code ${code}`);
    securegateProcess = null;
  });
}

function stopSecureGate() {
  if (securegateProcess) {
    console.log('Stopping SecureGate...');
    // Kill the process group or just the process
    securegateProcess.kill('SIGTERM');
    securegateProcess = null;
  }
}

module.exports = {
  startSecureGate,
  stopSecureGate
};
