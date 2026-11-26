// Created by anvex2012
'use strict';
/** Minimal glob → RegExp (supports **, *, ?, {a,b}) */
function globToRe(g) {
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*') {
      if (g[i + 1] === '*') { re += '.*'; i++; if (g[i + 1] === '/') i++; }
      else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else if (c === '{') { const end = g.indexOf('}', i); re += '(?:' + g.slice(i + 1, end).split(',').map((s) => s.replace(/[.+^$()|[\]\\]/g, '\\$&')).join('|') + ')'; i = end; }
    else re += c.replace(/[.+^$()|[\]\\]/g, '\\$&');
  }
  return new RegExp('(^|/)' + re + '$', 'i');
}
function matcher(globs = []) {
  const res = globs.filter(Boolean).map(globToRe);
  return (p) => res.some((r) => r.test(p.replace(/\\/g, '/')));
}
module.exports = { globToRe, matcher };
