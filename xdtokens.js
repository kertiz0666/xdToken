// Charset definitions
const _base36 = '0123456789abcdefghijklmnopqrstuvwxyz';
const _base62 = _base36 + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const _yolo = _base62 + '+/=~!@#$%^&*()[]{},.<>?|';

// Random generator from any charset
const _rand = (len, charset) => {
  let out = '';
  while (out.length < len) {
    out += Math.random().toString(36).slice(2);
  }
  return [...out].map(() => charset[Math.floor(Math.random() * charset.length)]).slice(0, len).join('');
};

// 1. _xdToken: structured ID using base36, with timestamp + pid + counter
const _xdToken = (() => {
  let counter = 0, last = 0;
  const epoch = 1700000000000;

  const pid = (typeof process !== "undefined" && process.pid)
    ? (process.pid % 1296).toString(36).padStart(2, '0')
    : Math.floor(Math.random() * 1296).toString(36).padStart(2, '0');

  return (len = 16) => {
    const now = Math.floor((Date.now() - epoch) / 1000);
    if (now !== last) {
      counter = 0;
      last = now;
    }

    const ts = (now % 46656).toString(36).padStart(3, '0');
    const ct = (counter++ % 46656).toString(36).padStart(3, '0');
    const base = ts + pid + ct;
    const fill = Math.max(0, len - base.length);

    return (base + _rand(fill, _base36)).slice(0, len);
  };
})();

// 2. _xdTokenSave: pure base62 (URL-safe)
const _xdTokenSave = (len = 16) => _rand(len, _base62);

// 3. _xdTokenYolo: full character set including unsafe symbols
const _xdTokenYolo = (len = 16) => _rand(len, _yolo);
