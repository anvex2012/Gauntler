// Creato da anvex2012
'use strict';
/* Starts Vite (hot reload) and Electron together */
const { spawn } = require('child_process');
const path = require('path');

(async () => {
  const { createServer } = await import('vite');
  const server = await createServer({ configFile: path.join(__dirname, '..', 'vite.config.mjs') });
  await server.listen();
  const url = server.resolvedUrls.local[0];
  console.log('Vite pronto su', url);
  const electron = require('electron');
  const child = spawn(electron, ['.'], { stdio: 'inherit', cwd: path.join(__dirname, '..'), env: { ...process.env, VITE_DEV_SERVER_URL: url } });
  child.on('close', async (code) => { await server.close(); process.exit(code || 0); });
})();
