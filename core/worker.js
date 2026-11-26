// Created by anvex2012
'use strict';
/* Worker thread: runs the analyses off the main thread */
const { parentPort } = require('worker_threads');
const { scanFile } = require('./index');
const i18n = require('./i18n');

parentPort.on('message', async ({ id, path, options }) => {
  if (options && options.lang) i18n.setLanguage(options.lang);
  try {
    const result = await scanFile(path, options || {});
    parentPort.postMessage({ id, result });
  } catch (e) {
    parentPort.postMessage({ id, error: e.message, code: e.code });
  }
});
