// Creato da anvex2012
'use strict';
const os = require('os');
const path = require('path');
const fs = require('fs');

/** Gauntler data folder (overridable with GAUNTLER_HOME) */
const HOME = process.env.GAUNTLER_HOME || path.join(os.homedir(), '.gauntler');

function dir(...p) {
  const d = path.join(HOME, ...p);
  fs.mkdirSync(d, { recursive: true });
  return d;
}
const file = (...p) => path.join(HOME, ...p);

module.exports = { HOME, dir, file };
