// â”€â”€ Dissect PE Helpers & Utilities â”€â”€
// Extracted from monolithic App.jsx â€” FAZ 7.1


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
  const out  = [];
  // ASCII
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
  // 19 — UTF-16LE
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

// —�—�—� String category classifier —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
const STR_PATTERNS = [
  { cat: 'url',       color: '#38bdf8', label: 'URL',        re: /^https?:\/\//i },
  { cat: 'ip',        color: '#fb923c', label: 'IP',         re: /^\d{1,3}(\.\d{1,3}){3}$/ },
  { cat: 'path',      color: '#a3e635', label: 'Path',       re: /^[A-Za-z]:\\/i },
  { cat: 'registry',  color: '#f472b6', label: 'Registry',   re: /^(HKEY_|HKLM|HKCU)/i },
  // 14 — anti-debug extended
  { cat: 'antidebug', color: '#f87171', label: 'AntiDebug',  re: /IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|ZwQueryInformationProcess|OutputDebugString|DebugBreak|SetUnhandledExceptionFilter|BlockInput|NtSetInformationThread|DebugActiveProcess|UnhandledExceptionFilter|RtlQueryProcessHeapInformation|NtGlobalFlag/i },
  // 15 — anti-vm extended
  { cat: 'antivm',    color: '#e879f9', label: 'AntiVM',     re: /vmware|virtualbox|vbox|qemu|sandbox|wine|cuckoomon|wireshark|ollydbg|x32dbg|x64dbg|procmon|processhacker|vmusrvc|vmtoolsd|vboxservice|vboxguest|vmwaretray|vmwareuser|vmhgfs|vmmouse|vmci|vboxsf|cpuid.*hypervisor|hypervisor.*bit/i },
  // 17 — new protection signatures
  { cat: 'protection',color: '#c084fc', label: 'Protection', re: /arxan|enigma|execryptor|nspack|obsidium|armadillo|acprotect|asprotect|safedisc|securom|starforce|steam_api|skidrow|codex\.nfo|reloaded\.nfo/i },
  { cat: 'crypto',    color: '#fbbf24', label: 'Crypto',     re: /AES|RSA|RC4|SHA|MD5|CryptAcquire|CryptEncrypt|BCrypt|CryptGenKey|RijndaelManaged|EVP_|mbedtls_|wolfSSL/i },
  { cat: 'network',   color: '#34d399', label: 'Network',    re: /socket|WSAStartup|connect|recv|send|HttpOpen|InternetOpen|WinHttpOpen|curl_|libcurl|gethostbyname/i },
  { cat: 'mutex',     color: '#c084fc', label: 'Mutex',      re: /CreateMutex|OpenMutex/i },
  // injection & ransomware indicators
  { cat: 'injection', color: '#f97316', label: 'Inject',     re: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetWindowsHookEx|RtlCreateUserThread/i },
  { cat: 'ransom',    color: '#ef4444', label: 'Ransom',     re: /your files.*encrypt|decrypt.*bitcoin|ransom|\.(locked|encrypted|enc)\b|vssadmin.*delete|wbadmin.*delete|shadow copy/i },
];

function classifyString(s) {
  for (const p of STR_PATTERNS) if (p.re.test(s)) return p;
  return null;
}

// —�—�—� Import Table parser —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
// 04 — Export Table extraction
function extractExports(data) {
  try {
    const v      = new DataView(data.buffer);
    const peOff  = v.getUint32(0x3C, true);
    const magic  = v.getUint16(peOff + 24, true);
    const is64   = magic === 0x20B;
    const numSec = v.getUint16(peOff + 6,  true);
    const optSize= v.getUint16(peOff + 20, true);
    const secBase= peOff + 24 + optSize;

    const exportRva = v.getUint32(peOff + 24 + (is64 ? 112 : 96), true);
    if (!exportRva) return [];

    const rvaToOff = rva => {
      for (let i = 0; i < numSec; i++) {
        const b = secBase + i * 40;
        const va = v.getUint32(b + 12, true), vsz = v.getUint32(b + 8, true), raw = v.getUint32(b + 20, true);
        if (rva >= va && rva < va + vsz) return raw + (rva - va);
      }
      return 0;
    };
    const readStr = off => { let s = ''; while (off < data.length && data[off]) s += String.fromCharCode(data[off++]); return s; };

    const expOff     = rvaToOff(exportRva);
    if (!expOff) return [];
    const ordBase    = v.getUint32(expOff + 16, true);
    const nNames     = v.getUint32(expOff + 24, true);
    const funcsOff   = rvaToOff(v.getUint32(expOff + 28, true));
    const namesOff   = rvaToOff(v.getUint32(expOff + 32, true));
    const ordsOff    = rvaToOff(v.getUint32(expOff + 36, true));
    if (!funcsOff || !namesOff || !ordsOff) return [];

    const exports = [];
    for (let i = 0; i < Math.min(nNames, 2000); i++) {
      const nameRva = v.getUint32(namesOff + i * 4, true);
      const ordIdx  = v.getUint16(ordsOff  + i * 2, true);
      const funcRva = v.getUint32(funcsOff + ordIdx * 4, true);
      exports.push({ name: readStr(rvaToOff(nameRva)), ordinal: ordBase + ordIdx, rva: `0x${funcRva.toString(16).toUpperCase().padStart(8, '0')}` });
    }
    return exports;
  } catch { return []; }
}

function extractImports(data) {
  try {
    const v = new DataView(data.buffer);
    const peOff  = v.getUint32(0x3C, true);
    const magic  = v.getUint16(peOff + 24, true);
    const is64   = magic === 0x20B;
    // import dir RVA is at different offsets for PE32 vs PE32+
    const idxOff = is64 ? peOff + 24 + 20 + 8 * 1 : peOff + 24 + 20 + 8 * 1; // DataDirectory[1]
    const dataDir1RvaOff = peOff + 24 + (is64 ? 112 : 96) + 8; // imports = dir[1]
    const importRva  = v.getUint32(dataDir1RvaOff, true);
    const importSize = v.getUint32(dataDir1RvaOff + 4, true);
    if (!importRva || !importSize) return [];

    const numSec  = v.getUint16(peOff + 6, true);
    const optSize = v.getUint16(peOff + 20, true);
    const secBase = peOff + 24 + optSize;

    // rva → file offset using section table
    const rvaToOff = (rva) => {
      for (let i = 0; i < numSec; i++) {
        const b    = secBase + i * 40;
        const va   = v.getUint32(b + 12, true);
        const vsz  = v.getUint32(b + 8,  true);
        const raw  = v.getUint32(b + 20, true);
        if (rva >= va && rva < va + vsz) return raw + (rva - va);
      }
      return 0;
    };

    const readStr = (off) => {
      let s = ''; if (!off) return s;
      while (off < data.length && data[off] !== 0) s += String.fromCharCode(data[off++]);
      return s;
    };

    const imports = [];
    let descOff = rvaToOff(importRva);
    for (let d = 0; d < 200; d++) {
      const nameRva = v.getUint32(descOff + 12, true);
      const iltRva  = v.getUint32(descOff, true) || v.getUint32(descOff + 16, true);
      if (!nameRva && !iltRva) break;
      const dllName = readStr(rvaToOff(nameRva)).toLowerCase();
      if (!dllName) break;
      const funcs = [];
      let iltOff = rvaToOff(iltRva);
      for (let f = 0; f < 300; f++) {
        const entry = is64 ? (Number(v.getBigUint64(iltOff, true)) & 0x7fffffff) : v.getUint32(iltOff, true);
        if (!entry) break;
        const isOrdinal = is64 ? !!(Number(v.getBigUint64(iltOff, true)) >>> 63) : !!(entry >>> 31);
        if (!isOrdinal) {
          const hintOff = rvaToOff(entry & (is64 ? 0x7fffffff : 0x7fffffff));
          if (hintOff) funcs.push(readStr(hintOff + 2));
        } else {
          funcs.push(`Ordinal#${entry & 0xffff}`);
        }
        iltOff += is64 ? 8 : 4;
      }
      imports.push({ dll: dllName, funcs });
      descOff += 20;
    }
    return imports;
  } catch { return []; }
}

// —�—�—� Packer signatures (16) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
const PACKER_SEC_SIGS = [
  { name: 'UPX',       re: /^\.upx[012]?$/i },
  { name: 'MPRESS',    re: /^\.mpress[12]$/i },
  { name: 'ASPack',    re: /^\.aspack$/i },
  { name: 'Petite',    re: /^\.petite$/i },
  { name: 'PECompact', re: /^\.pec[12]?$/i },
  { name: 'NSPack',    re: /^nsp/i },
  { name: 'tElock',    re: /^\.te!$/i },
  { name: 'EXEcryptor',re: /^\.exeC/i },
  { name: 'Enigma',    re: /^enigma[12]/i },
];
const PACKER_EP_SIGS = [
  { name: 'UPX',    sig: [0x60, 0xBE] },
  { name: 'MPRESS', sig: [0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58] },
  { name: 'ASPack', sig: [0x60, 0xE8, 0x72, 0x00] },
  { name: 'FSG',    sig: [0xBE, 0x88] },
];

// —�—�—� YARA-like built-in rules (12) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
const YARA_RULES = [
  { id: 'denuvo_drm',     name: 'Denuvo Anti-Tamper',      sev: 'critical', match: r => r.denuvo },
  { id: 'vmp_protect',    name: 'VMProtect',               sev: 'critical', match: r => r.vmp },
  { id: 'themida',        name: 'Themida Protection',      sev: 'critical', match: r => r.themida },
  { id: 'anti_trifecta',  name: 'Anti-Analysis Trifecta',  sev: 'critical', match: r => r.antiDebug && r.antiVM && r.overallEntropy > 7.0,  desc: 'Anti-debug + Anti-VM + Yüksek entropi kombinasyonu' },
  { id: 'high_entropy_x', name: 'High Entropy Exec Section',sev: 'high',   match: r => r.sections.some(s => s.isExec && s.entropy > 7.5),  desc: 'Yürütülebilir section yüksek entropi (şifreli/packed kod)' },
  { id: 'crypto_net',     name: 'Crypto + Network',        sev: 'high',    match: r => r.strings?.some(s => s.cat?.cat === 'crypto') && r.strings?.some(s => s.cat?.cat === 'network'), desc: 'C2 beacon veya _ifreli ileti_im belirtisi' },
  { id: 'ip_hardcoded',   name: 'Hardcoded IP',            sev: 'high',    match: r => r.strings?.some(s => s.cat?.cat === 'ip') },
  { id: 'anti_debug',     name: 'Anti-Debug Detected',     sev: 'high',    match: r => r.antiDebug },
  { id: 'anti_vm',        name: 'Anti-VM Detected',        sev: 'high',    match: r => r.antiVM },
  { id: 'packer_found',   name: 'Packer Detected',         sev: 'warn',    match: r => r.packers?.length > 0, desc: r => `Tespit edilen packer(lar): ${r.packers?.join(', ')}` },
  { id: 'url_embedded',   name: 'Embedded URL',            sev: 'medium',  match: r => r.strings?.some(s => s.cat?.cat === 'url') },
  { id: 'registry_access',name: 'Registry Access',         sev: 'medium',  match: r => r.strings?.some(s => s.cat?.cat === 'registry') },
  { id: 'mutex_creation', name: 'Mutex Creation',          sev: 'medium',  match: r => r.strings?.some(s => s.cat?.cat === 'mutex') },
  { id: 'many_suspicious',name: 'Multiple Suspicious Sections', sev: 'medium', match: r => r.suspiciousCount >= 3 },
  { id: 'no_imports',     name: 'Zero Imports (Suspicious)',sev: 'high',   match: r => (r.imports?.length || 0) === 0 },
  // 58 — extra YARA-style rules —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
  { id: 'clr_dotnet',    name: '.NET CLR Binary',          sev: 'warn',   match: r => r.isDotNet },
  { id: 'zero_ep',       name: 'Suspicious Zero Entry Point', sev: 'high', match: r => r.ep === 0 && (r.imports?.length || 0) > 0, desc: 'Entry point at 0x0 with imports — unusual, may indicate reflective loading' },
  { id: 'rich_header',   name: 'Rich Header Present',      sev: 'medium', match: r => !!r.richHash, desc: r => `Rich hash: ${r.richHash}` },
  { id: 'overlay_large', name: 'Large Overlay Data',       sev: 'warn',   match: r => r.overlaySize > 0, desc: r => `${(r.overlaySize/1024).toFixed(1)} KB overlay data appended after PE` },
  { id: 'multi_packers', name: 'Multiple Packers Stacked', sev: 'critical', match: r => (r.packers?.length || 0) >= 2, desc: r => `Double-packed: ${r.packers?.join(' + ')}` },
];
const YARA_SEV_COLOR = { critical: '#f87171', high: '#fb923c', warn: '#fbbf24', medium: '#60a5fa' };

// —�—�—� Scan History helpers (21 + 22) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
const HISTORY_KEY = 'dissect_scan_history';
// Plugin hook registry (FAZ 5) — placed early for use in addToHistory
const _pluginHooks = { onScan: [], onPatch: [], onDisassemble: [], commands: [], views: [], aiQueries: [] };
function firePluginHook(hookName, data) {
  (_pluginHooks[hookName] || []).forEach(fn => { try { fn(data); } catch (e) { console.warn('[Plugin hook error]', hookName, e); } });
}
function getPluginCommands() { return _pluginHooks.commands; }
function getPluginViews() { return _pluginHooks.views; }

function getHistory()  { try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; } }
function addToHistory(fileName, result) {
  const hist  = getHistory().slice(0, 19);
  localStorage.setItem(HISTORY_KEY, JSON.stringify([{ id: Date.now(), ts: new Date().toISOString(), fileName, riskScore: result.riskScore, arch: result.arch, denuvo: result.denuvo, vmp: result.vmp, antiDebug: result.antiDebug, packers: result.packers, result }, ...hist]));
  try { firePluginHook('onScan', { ...result, fileName }); } catch (e) { console.warn('[Plugin onScan]', e); }
}
// G4 — starred scans
const STARRED_KEY = 'dissect_starred';
function getStarred() { try { return new Set(JSON.parse(localStorage.getItem(STARRED_KEY) || '[]')); } catch { return new Set(); } }
function toggleStarred(id) {
  const s = getStarred();
  if (s.has(id)) s.delete(id); else s.add(id);
  localStorage.setItem(STARRED_KEY, JSON.stringify([...s]));
  return s;
}
// 25 — per-scan notes
const NOTES_KEY = 'dissect_scan_notes';
function getNotes() { try { return JSON.parse(localStorage.getItem(NOTES_KEY) || '{}'); } catch { return {}; } }
function saveNote(id, text) {
  const notes = getNotes();
  if (text?.trim()) notes[id] = text.trim(); else delete notes[id];
  localStorage.setItem(NOTES_KEY, JSON.stringify(notes));
}

// F5 — CRC32 table (precomputed once)
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

// F5 — MD5 (compact pure-JS)
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

async function analyzePE(data) {
  const v = new DataView(data.buffer);
  if (v.getUint16(0, true) !== 0x5A4D) throw new Error('Not a valid executable — missing MZ signature');
  const peOff  = v.getUint32(0x3C, true);
  if (v.getUint32(peOff, true) !== 0x00004550) throw new Error('Invalid PE signature');
  const numSec  = v.getUint16(peOff + 6,  true);
  const optSize = v.getUint16(peOff + 20, true);
  const ep      = v.getUint32(peOff + 40, true);
  const magic   = v.getUint16(peOff + 24, true);
  const arch    = magic === 0x20B ? 'x64' : 'x86';
  const secBase = peOff + 24 + optSize;

  // 08 — Compile timestamp
  const compiledTs = v.getUint32(peOff + 8, true);
  const compiledAt = compiledTs > 0 ? new Date(compiledTs * 1000) : null;
  const fakeTimestamp = compiledAt && (compiledAt.getFullYear() < 1995 || compiledAt > new Date());

  // 10 — Rich Header (between DOS stub and PE signature)
  let richHash = null;
  try {
    const richMagic = 0x68636952; // 'Rich'
    const dancMagic = 0x536E6144; // 'DanS'
    for (let i = 0x80; i < peOff - 4; i += 4) {
      if (v.getUint32(i, true) === richMagic) {
        const key = v.getUint32(i + 4, true);
        // collect entries between DanS..Rich xor with key
        const entries = [];
        for (let j = 0x80; j < i; j += 8) {
          const cv  = v.getUint32(j, true) ^ key;
          const cnt = v.getUint32(j + 4, true) ^ key;
          if (cv === dancMagic) continue;
          const prodId = (cv >> 16) & 0xFFFF;
          const vsId   = cv & 0xFFFF;
          if (prodId || vsId) entries.push(`${prodId.toString(16).padStart(4,'0')}.${vsId.toString(16).padStart(4,'0')}:${cnt}`);
        }
        if (entries.length) richHash = entries.slice(0, 12).join(' | ');
        break;
      }
    }
  } catch {}

  // 06 — .NET CLR / COM descriptor (DataDirectory[14])
  const is64hdr  = (v.getUint16(peOff + 24, true) === 0x20B);
  const dirBase  = peOff + 24 + (is64hdr ? 112 : 96);
  const clrRva   = v.getUint32(dirBase + 14 * 8, true);
  const isDotNet = clrRva > 0;

  // 09 — Checksum validation (simple field check — non-zero is suspicious if not DLL/driver)
  const peChecksum  = v.getUint32(peOff + 24 + 64, true);  // OptionalHeader.CheckSum
  const subsystem   = v.getUint16(peOff + 24 + (is64hdr ? 68 : 68), true);
  const isDll       = !!(v.getUint16(peOff + 22, true) & 0x2000);
  const checksumOk  = peChecksum === 0 ? null : true; // we can't recompute in browser cheaply, flag if missing

  // 07 — Overlay detection (data after last section)
  let overlayOffset = 0, overlaySize = 0;
  for (let i = 0; i < numSec; i++) {
    const b   = secBase + i * 40;
    const raw = v.getUint32(b + 20, true);
    const rsz = v.getUint32(b + 16, true);
    const end = raw + rsz;
    if (end > overlayOffset) overlayOffset = end;
  }
  if (overlayOffset > 0 && data.length > overlayOffset + 512) {
    overlaySize = data.length - overlayOffset;
  }

  const sections = [];
  let denuvo = false, vmp = false, themida = false;

  for (let i = 0; i < numSec; i++) {
    const b     = secBase + i * 40;
    let name    = '';
    for (let j = 0; j < 8; j++) { const ch = v.getUint8(b + j); if (!ch) break; name += String.fromCharCode(ch); }
    const vsize  = v.getUint32(b + 8,  true);
    const vaddr  = v.getUint32(b + 12, true);
    const rsize  = v.getUint32(b + 16, true);
    const rptr   = v.getUint32(b + 20, true);
    const chars  = v.getUint32(b + 36, true);
    const isExec = !!(chars & 0x20000000);
    const writable = !!(chars & 0x80000000);
    const sample = data.slice(rptr, rptr + Math.min(rsize, 65536));
    const entropy = calcEntropy(sample);
    const lo      = name.toLowerCase();

    if (lo.includes('denuvo') || (entropy > 7.55 && rsize > 512 * 1024 && isExec)) denuvo = true;
    if (lo.includes('.vmp'))     vmp     = true;
    if (lo.includes('.themida')) themida = true;

    sections.push({ name: name || '(unnamed)', vsize, vaddr, rsize, rawOff: rptr, entropy, isExec, writable, suspicious: entropy > 7.2 && rsize > 4096 });
  }

  const overallEntropy  = calcEntropy(data.slice(0, Math.min(data.length, 524288)));
  const suspiciousCount = sections.filter(s => s.suspicious).length;
  const rawStrings      = extractStrings(data.slice(0, Math.min(data.length, 2 * 1024 * 1024)));
  const strings         = rawStrings.map(s => ({ text: s, cat: classifyString(s) }));
  const imports         = extractImports(data);

  // anti-debug & anti-vm from imports + strings
  const allText = rawStrings.join(' ') + imports.flatMap(i => i.funcs).join(' ');
  const antiDebug = STR_PATTERNS.find(p => p.cat === 'antidebug')?.re.test(allText) || false;
  const antiVM    = STR_PATTERNS.find(p => p.cat === 'antivm')?.re.test(allText) || false;

  // 16 — Packer detection (section names + EP byte sigs)
  const packers = [];
  for (const sec of sections) {
    for (const sig of PACKER_SEC_SIGS)
      if (sig.re.test(sec.name) && !packers.includes(sig.name)) packers.push(sig.name);
  }
  // EP file offset
  let epFileOff = 0;
  for (let i = 0; i < numSec; i++) {
    const b  = secBase + i * 40;
    const va = v.getUint32(b + 12, true), vsz = v.getUint32(b + 8, true), raw = v.getUint32(b + 20, true);
    if (ep >= va && ep < va + vsz) { epFileOff = raw + (ep - va); break; }
  }
  if (epFileOff > 0 && epFileOff + 16 < data.length) {
    for (const ps of PACKER_EP_SIGS)
      if (!packers.includes(ps.name) && ps.sig.every((b, i) => data[epFileOff + i] === b)) packers.push(ps.name);
  }

  const riskScore = Math.min(100, Math.round(
    (denuvo ? 60 : 0) + (vmp ? 35 : 0) + (themida ? 25 : 0) +
    (overallEntropy > 7.0 ? 15 : overallEntropy > 6.5 ? 8 : 0) +
    suspiciousCount * 5 +
    (antiDebug ? 10 : 0) + (antiVM ? 8 : 0) +
    packers.length * 12 +
    (overlaySize > 0 ? 10 : 0) +
    (fakeTimestamp ? 8 : 0)
  ));

  // 04 — Export table
  const exports = extractExports(data);

  // 18 — Browser-side hashes (SHA-256 + SHA-1)
  let sha256 = null, sha1 = null;
  try {
    const buf = data.buffer.slice ? data.buffer.slice(0, data.length) : data.buffer;
    const [h256, h1] = await Promise.all([
      crypto.subtle.digest('SHA-256', buf),
      crypto.subtle.digest('SHA-1',   buf),
    ]);
    const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
    sha256 = toHex(h256);
    sha1   = toHex(h1);
  } catch {}

  // 20 — Imphash (SHA-1 of normalised import CSV)
  let imphash = null;
  try {
    if (imports.length > 0) {
      const csv = imports.flatMap(imp => {
        const dll = imp.dll.replace(/\.(dll|ocx|sys)$/i, '').toLowerCase();
        return imp.funcs.map(fn => `${dll}.${fn.toLowerCase()}`);
      }).join(',');
      const h = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(csv));
      imphash = Array.from(new Uint8Array(h)).map(x => x.toString(16).padStart(2,'0')).join('');
    }
  } catch {}

  return { ep, arch, numSec, sections, denuvo, vmp, themida, overallEntropy, suspiciousCount, riskScore, strings, imports, antiDebug, antiVM, packers, exports, compiledAt: compiledAt?.toISOString() || null, fakeTimestamp: !!fakeTimestamp, sha256, sha1, imphash, isDotNet, isDll, overlaySize, richHash, checksumOk,
    // A3 — EP bytes for inline disasm view
    epBytes: (() => {
      if (epFileOff > 0 && epFileOff + 8 < data.length) {
        const slice = data.slice(epFileOff, Math.min(epFileOff + 256, data.length));
        return Array.from(slice).map(b => b.toString(16).padStart(2,'0').toUpperCase());
      }
      return [];
    })(),
    epFileOff,
    // A4 — Code caves: zero-runs >= 16 bytes in exec sections
    codeCaves: (() => {
      const caves = [];
      for (const sec of sections) {
        if (!sec.isExec) continue;
        const raw = sec.rawOff || 0; const rsz = sec.rsize;
        if (!raw || !rsz) continue;
        let run = 0, runStart = 0;
        for (let i = 0; i < rsz && i + raw < data.length; i++) {
          if (data[raw + i] === 0x00) { if (run === 0) runStart = i; run++; }
          else { if (run >= 16) caves.push({ section: sec.name, fileOff: raw + runStart, size: run }); run = 0; }
        }
        if (run >= 16) caves.push({ section: sec.name, fileOff: raw + (rsz - run), size: run });
        if (caves.length > 50) break;
      }
      return caves.sort((a,b) => b.size - a.size).slice(0, 20);
    })(),
    // B5 — Sections with WRX (writable + executable) flag combo
    wrxSections: sections.filter(s => s.writable && s.isExec).map(s => s.name),
    // B7 — Packing ratios
    packingRatios: sections.map(s => ({ name: s.name, raw: s.rsize, virt: s.vsize, ratio: s.vsize > 0 ? (s.rsize / s.vsize).toFixed(3) : '—' })),
    // F5 — Multi-hash (MD5 + CRC32; SHA-256 + SHA-1 computed below via WebCrypto)
    md5:   calcMD5(data),
    crc32: calcCRC32(data),
    // B2 — TLS: detect .tls section
    hasTls: sections.some(s => s.name.startsWith('.tls') || s.name.toUpperCase().startsWith('TLS')),
    // B3 — Exception .pdata entry count (each RUNTIME_FUNCTION = 12 bytes)
    exceptionEntries: (() => {
      const p = sections.find(s => s.name === '.pdata');
      return p ? Math.floor(p.rsize / 12) : 0;
    })(),
    // B4 — Delayed imports via data directory #13
    delayedImports: (() => {
      try {
        const ddOff  = peOff + 24 + (is64hdr ? 112 : 96) + 13 * 8;
        const ddRva  = v.getUint32(ddOff, true);
        if (!ddRva) return [];
        // Find file offset for ddRva
        let ddFOff = 0;
        for (let i = 0; i < numSec; i++) {
          const b   = secBase + i * 40;
          const va  = v.getUint32(b + 12, true);
          const vsz = v.getUint32(b + 8, true);
          const raw = v.getUint32(b + 20, true);
          if (ddRva >= va && ddRva < va + vsz) { ddFOff = raw + (ddRva - va); break; }
        }
        if (!ddFOff) return [];
        const names = [];
        for (let i = ddFOff; i + 32 <= data.length; i += 32) {
          const attribs = v.getUint32(i, true);
          if (attribs === 0) break; // null descriptor = end
          const nameRva = v.getUint32(i + 4, true);
          if (!nameRva) break;
          // RVA ? file offset
          let nameFOff = 0;
          for (let j = 0; j < numSec; j++) {
            const b   = secBase + j * 40;
            const va  = v.getUint32(b + 12, true);
            const vsz = v.getUint32(b + 8, true);
            const raw = v.getUint32(b + 20, true);
            if (nameRva >= va && nameRva < va + vsz) { nameFOff = raw + (nameRva - va); break; }
          }
          if (!nameFOff) continue;
          let name = ''; let k = nameFOff;
          while (k < data.length && data[k] !== 0 && name.length < 128) name += String.fromCharCode(data[k++]);
          if (name) names.push(name);
          if (names.length > 50) break;
        }
        return names;
      } catch { return []; }
    })(),
    // B8 — Debug PDB path (scan for RSDS CodeView signature)
    debugPdb: (() => {
      for (let i = 0; i < data.length - 28; i++) {
        if (data[i]===0x52 && data[i+1]===0x53 && data[i+2]===0x44 && data[i+3]===0x53) {
          const start = i + 24; let end = start;
          while (end < data.length && data[end] !== 0 && end - start < 260) end++;
          const s = new TextDecoder('utf-8', { fatal: false }).decode(data.slice(start, end));
          if (s.endsWith('.pdb') || (s.length > 4 && (s.includes('\\') || s.includes('/')))) return s;
        }
      }
      return '';
    })(),
    // B1 — Resource extraction: parse PE resource directory (type 3=icon, 14=manifest, 16=version)
    resources: (() => {
      try {
        const e_lfanew = new DataView(data.buffer).getUint32(0x3c, true);
        const peR = new DataView(data.buffer);
        const numSections = peR.getUint16(e_lfanew + 6, true);
        const optHdrSz = peR.getUint16(e_lfanew + 20, true);
        const sectionHdrOff = e_lfanew + 24 + optHdrSz;
        const is64 = peR.getUint16(e_lfanew + 24, true) === 0x20b;
        const rsrcDirIdxInOptHdr = is64 ? (0x70 + 16*2 + 4) : (0x60 + 16*2); // opt header resource entry offset
        const rsrcRva = peR.getUint32(e_lfanew + 24 + (is64 ? 0x70 : 0x60) + 16*2, true);
        const rsrcSize = peR.getUint32(e_lfanew + 24 + (is64 ? 0x70 : 0x60) + 16*2 + 4, true);
        if (!rsrcRva || !rsrcSize) return [];
        // Find raw offset of .rsrc section
        let rsrcRaw = 0, rsrcVA = 0;
        for (let si = 0; si < numSections; si++) {
          const off = sectionHdrOff + si * 40;
          const vAddr = peR.getUint32(off + 12, true);
          const vSz   = peR.getUint32(off + 8, true);
          if (rsrcRva >= vAddr && rsrcRva < vAddr + vSz) {
            rsrcRaw = peR.getUint32(off + 20, true) + (rsrcRva - vAddr);
            rsrcVA  = vAddr;
            break;
          }
        }
        if (!rsrcRaw) return [];
        const rsrcBase = rsrcRaw - (rsrcRva - rsrcVA);
        const readDir = (dirOff) => {
          const named = peR.getUint16(dirOff + 12, true);
          const id    = peR.getUint16(dirOff + 14, true);
          const entries = [];
          for (let i = 0; i < named + id; i++) {
            const entOff = dirOff + 16 + i * 8;
            const nameOrId = peR.getUint32(entOff, true);
            const dataOff  = peR.getUint32(entOff + 4, true);
            entries.push({ id: nameOrId & 0x7FFFFFFF, isName: !!(nameOrId & 0x80000000), childOff: dataOff & 0x7FFFFFFF, isDir: !!(dataOff & 0x80000000) });
          }
          return entries;
        };
        const rsrcDirStart = rsrcRaw - (rsrcRva - rsrcVA) + (rsrcRva - (rsrcRaw - (rsrcRaw - (rsrcRva - rsrcVA))));
        // Parse root directory
        const resources = [];
        const TYPE_NAMES = { 1: 'Cursor', 2: 'Bitmap', 3: 'Icon', 4: 'Menu', 5: 'Dialog', 6: 'String', 9: 'Accelerator', 10: 'RCData', 14: 'Manifest', 16: 'VersionInfo', 17: 'Toolbar' };
        const rootOff = rsrcRaw - (rsrcRva - rsrcVA) + (rsrcRva - (rsrcRaw - (rsrcRaw - (rsrcRva - rsrcVA))));
        // Simplified: just read first-level type directory
        const numNamed = peR.getUint16(rsrcRaw + 12, true);
        const numId    = peR.getUint16(rsrcRaw + 14, true);
        for (let i = 0; i < Math.min(numNamed + numId, 32); i++) {
          const entOff = rsrcRaw + 16 + i * 8;
          if (entOff + 8 > data.length) break;
          const typeId = peR.getUint32(entOff, true) & 0x7FFFFFFF;
          const typeIsDir = !!(peR.getUint32(entOff + 4, true) & 0x80000000);
          const subDirOff = (peR.getUint32(entOff + 4, true) & 0x7FFFFFFF) + rsrcRaw - rsrcRva + rsrcVA;
          if (typeIsDir && subDirOff < data.length - 16) {
            const numSubNamed = peR.getUint16(subDirOff + 12, true);
            const numSubId    = peR.getUint16(subDirOff + 14, true);
            const count = numSubNamed + numSubId;
            resources.push({ type: typeId, name: TYPE_NAMES[typeId] || `Type${typeId}`, count });
          }
        }
        return resources;
      } catch { return []; }
    })(),
  };
}

// —�—�—� Shared atoms —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

export {
  calcEntropy, extractStrings, STR_PATTERNS, classifyString,
  extractExports, extractImports,
  PACKER_SEC_SIGS, PACKER_EP_SIGS, YARA_RULES, YARA_SEV_COLOR,
  HISTORY_KEY, STARRED_KEY,
  _pluginHooks, getPluginCommands,
  getHistory, addToHistory, getStarred, toggleStarred,
  CRC32_TABLE, calcCRC32, calcMD5,
  analyzePE, getNotes, saveNote, getPluginViews,
};