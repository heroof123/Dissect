// Dissect — Heavy computation Web Worker
// Offloads: calcEntropy, extractStrings, classifyString, calcCRC32, calcMD5

const STR_PATTERNS = [
  { cat: 'url',       color: '#38bdf8', label: 'URL',        re: /^https?:\/\//i },
  { cat: 'ip',        color: '#fb923c', label: 'IP',         re: /^\d{1,3}(\.\d{1,3}){3}$/ },
  { cat: 'path',      color: '#a3e635', label: 'Path',       re: /^[A-Za-z]:\\/i },
  { cat: 'registry',  color: '#f472b6', label: 'Registry',   re: /^(HKEY_|HKLM|HKCU)/i },
  { cat: 'antidebug', color: '#f87171', label: 'AntiDebug',  re: /IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|ZwQueryInformationProcess|OutputDebugString|DebugBreak|SetUnhandledExceptionFilter|BlockInput|NtSetInformationThread|DebugActiveProcess|UnhandledExceptionFilter|RtlQueryProcessHeapInformation|NtGlobalFlag/i },
  { cat: 'antivm',    color: '#e879f9', label: 'AntiVM',     re: /vmware|virtualbox|vbox|qemu|sandbox|wine|cuckoomon|wireshark|ollydbg|x32dbg|x64dbg|procmon|processhacker|vmusrvc|vmtoolsd|vboxservice|vboxguest|vmwaretray|vmwareuser|vmhgfs|vmmouse|vmci|vboxsf|cpuid.*hypervisor|hypervisor.*bit/i },
  { cat: 'protection',color: '#c084fc', label: 'Protection', re: /arxan|enigma|execryptor|nspack|obsidium|armadillo|acprotect|asprotect|safedisc|securom|starforce|steam_api|skidrow|codex\.nfo|reloaded\.nfo/i },
  { cat: 'crypto',    color: '#fbbf24', label: 'Crypto',     re: /AES|RSA|RC4|SHA|MD5|CryptAcquire|CryptEncrypt|BCrypt|CryptGenKey|RijndaelManaged|EVP_|mbedtls_|wolfSSL/i },
  { cat: 'network',   color: '#34d399', label: 'Network',    re: /socket|WSAStartup|connect|recv|send|HttpOpen|InternetOpen|WinHttpOpen|curl_|libcurl|gethostbyname/i },
  { cat: 'mutex',     color: '#c084fc', label: 'Mutex',      re: /CreateMutex|OpenMutex/i },
  { cat: 'injection', color: '#f97316', label: 'Inject',     re: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetWindowsHookEx|RtlCreateUserThread/i },
  { cat: 'ransom',    color: '#ef4444', label: 'Ransom',     re: /your files.*encrypt|decrypt.*bitcoin|ransom|\.(locked|encrypted|enc)\b|vssadmin.*delete|wbadmin.*delete|shadow copy/i },
];

function classifyString(s) {
  for (const p of STR_PATTERNS) if (p.re.test(s)) return p;
  return null;
}

function calcEntropy(data) {
  if (!data.length) return 0;
  const c = new Uint32Array(256);
  for (const b of data) c[b]++;
  let e = 0;
  for (const n of c) if (n > 0) { const p = n / data.length; e -= p * Math.log2(p); }
  return e;
}

function extractStrings(data, minLen = 5) {
  const seen = new Set();
  const out = [];
  let cur = '';
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (b >= 0x20 && b < 0x7f) { cur += String.fromCharCode(b); }
    else {
      if (cur.length >= minLen && !seen.has(cur)) { seen.add(cur); out.push(cur); }
      cur = '';
      if (out.length > 800) break;
    }
  }
  let ucur = '';
  for (let i = 0; i + 1 < data.length && out.length < 1200; i += 2) {
    const cp = data[i] | (data[i + 1] << 8);
    if (cp >= 0x20 && cp < 0x7f) { ucur += String.fromCharCode(cp); }
    else {
      if (ucur.length >= minLen && !seen.has(ucur)) { seen.add(ucur); out.push(ucur); }
      ucur = '';
    }
  }
  return out;
}

const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c;
  }
  return t;
})();

function calcCRC32(data) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) crc = CRC32_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
  return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16).toUpperCase().padStart(8, '0');
}

function calcMD5(data) {
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  const msg = [...data];
  const len8 = data.length;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const bits = len8 * 8;
  for (let i = 0; i < 8; i++) msg.push((bits / Math.pow(256, i)) & 0xFF);
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  for (let i = 0; i < msg.length; i += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) M[j] = msg[i+j*4] | (msg[i+j*4+1]<<8) | (msg[i+j*4+2]<<16) | (msg[i+j*4+3]<<24);
    let [A, B, C, D] = [a, b, c, d];
    for (let j = 0; j < 64; j++) {
      let F, g;
      if (j < 16)      { F = (B & C) | (~B & D); g = j; }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5*j+1) % 16; }
      else if (j < 48) { F = B ^ C ^ D;            g = (3*j+5) % 16; }
      else             { F = C ^ (B | ~D);          g = (7*j) % 16; }
      const temp = D; D = C; C = B;
      const r = S[j]; const x = (A + F + K[j] + M[g]) >>> 0;
      B = (B + ((x << r) | (x >>> (32 - r)))) >>> 0;
      A = temp;
    }
    a = (a + A) >>> 0; b = (b + B) >>> 0; c = (c + C) >>> 0; d = (d + D) >>> 0;
  }
  return [a,b,c,d].map(n => [(n)&0xFF,(n>>8)&0xFF,(n>>16)&0xFF,(n>>24)&0xFF].map(x=>x.toString(16).padStart(2,'0')).join('')).join('');
}

// Message handler
self.onmessage = function(e) {
  const { id, type, data } = e.data;
  try {
    let result;
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    switch (type) {
      case 'entropy':
        result = calcEntropy(bytes);
        break;
      case 'strings':
        result = extractStrings(bytes).map(s => ({ text: s, cat: classifyString(s) }));
        break;
      case 'crc32':
        result = calcCRC32(bytes);
        break;
      case 'md5':
        result = calcMD5(bytes);
        break;
      case 'all': {
        const entropy = calcEntropy(bytes);
        const strings = extractStrings(bytes).map(s => ({ text: s, cat: classifyString(s) }));
        const crc32 = calcCRC32(bytes);
        const md5 = calcMD5(bytes);
        result = { entropy, strings, crc32, md5 };
        break;
      }
      default:
        throw new Error(`Unknown task type: ${type}`);
    }
    self.postMessage({ id, result });
  } catch (err) {
    self.postMessage({ id, error: err.message });
  }
};
