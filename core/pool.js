// Created by anvex2012
'use strict';
const { t } = require('./i18n');
/**
 * Pool of worker threads: N parallel analyses, each in its own thread.
 * A file that exceeds the timeout gets its thread terminated (and replaced) without blocking the others.
 * Used by both the CLI and the Electron app.
 */
const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');

class ScanPool {
  constructor({ size = 0, timeoutMs = 15 * 60 * 1000 } = {}) {
    this.size = size > 0 ? size : Math.max(1, Math.min(os.cpus().length, 8));
    this.timeoutMs = timeoutMs;
    this.workers = [];
    this.queue = [];
    this.seq = 0;
    this.closed = false;
  }

  _spawn() {
    const w = new Worker(path.join(__dirname, 'worker.js'));
    w.job = null;
    w.on('message', (msg) => {
      const job = w.job;
      if (!job || msg.id !== job.id) return;
      clearTimeout(job.timer);
      w.job = null;
      msg.error ? job.reject(Object.assign(new Error(msg.error), { code: msg.code })) : job.resolve(msg.result);
      this._next();
    });
    w.on('error', (e) => this._fail(w, e));
    w.on('exit', (code) => { if (w.job) this._fail(w, new Error(t('Worker terminato (codice {code})', { code }))); });
    w.unref();
    this.workers.push(w);
    return w;
  }

  _fail(w, err) {
    const job = w.job;
    w.job = null;
    this.workers = this.workers.filter((x) => x !== w);
    if (job) { clearTimeout(job.timer); job.reject(err); }
    if (!this.closed) this._next();
  }

  _next() {
    if (this.closed) return;
    while (this.queue.length) {
      let w = this.workers.find((x) => !x.job);
      if (!w && this.workers.length < this.size) w = this._spawn();
      if (!w) return;
      const job = this.queue.shift();
      w.job = job;
      w.ref();
      job.timer = setTimeout(() => {
        const err = Object.assign(new Error(t('Tempo massimo superato ({n} s)', { n: Math.round(this.timeoutMs / 1000) })), { code: 'TIMEOUT' });
        w.terminate();
        this._fail(w, err);
      }, this.timeoutMs);
      w.postMessage({ id: job.id, path: job.path, options: job.options });
    }
    for (const w of this.workers) if (!w.job) w.unref();
  }

  scan(filePath, options = {}) {
    return new Promise((resolve, reject) => {
      this.queue.push({ id: ++this.seq, path: filePath, options, resolve, reject });
      this._next();
    });
  }

  get busy() { return this.workers.filter((w) => w.job).length + this.queue.length; }

  async close() {
    this.closed = true;
    for (const j of this.queue) j.reject(new Error(t('Annullato')));
    this.queue = [];
    await Promise.all(this.workers.map((w) => w.terminate()));
    this.workers = [];
  }
}

module.exports = { ScanPool };
