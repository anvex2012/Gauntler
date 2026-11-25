// Creato da anvex2012
'use strict';
/* Worker thread: runs the analyses off the main thread */
const { parentPort } = require('worker_threads');
const { scanFile } = require('./index');

parentPort.on('message', async ({ id, path, options }) => {
  try {
    const result = await scanFile(path, options || {});
    parentPort.postMessage({ id, result });
  } catch (e) {
    parentPort.postMessage({ id, error: e.message, code: e.code });
  }
});
