import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState, MarkerType,
} from '@xyflow/react';
import dagre from 'dagre';
import '@xyflow/react/dist/style.css';
import {
  Zap, Microscope, ShieldAlert, Binary, Minus, Maximize2, Square, X,
  AlertTriangle, ShieldCheck, FileSearch, ChevronRight, ChevronLeft,
  Plus, Trash2, Play, Cpu, Bot, FolderOpen, Download,
  RefreshCw, Monitor, HardDrive, MemoryStick, Layers, Send,
  Terminal, CircleDot, CheckCircle2, XCircle, MessageSquare,
  Network, Code, Search, ArrowUp, ArrowDown, List, GitBranch,
  ChevronDown, Copy, BarChart2
} from 'lucide-react';

// —�—�—� PE Helpers (runs in browser) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

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

function WinBtn({ onClick, danger, children }) {
  const [h, setH] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{ width: 34, height: 34, border: 'none', cursor: 'pointer', borderRadius: 8, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: h ? (danger ? 'rgba(239,68,68,0.16)' : 'rgba(255,255,255,0.09)') : 'transparent', color: h ? (danger ? '#f87171' : '#e2e8f0') : '#4b5563', transition: 'all 0.13s' }}>
      {children}
    </button>
  );
}

function NavItem({ active, onClick, icon, label, sub, badge }) {
  const [h, setH] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{ width: '100%', border: 'none', cursor: 'pointer', borderRadius: 8, padding: '10px 11px', textAlign: 'left', display: 'flex', alignItems: 'center', gap: 10, background: active ? 'rgba(99,102,241,0.11)' : h ? 'rgba(255,255,255,0.04)' : 'transparent', borderLeft: `2px solid ${active ? '#6366f1' : 'transparent'}`, marginBottom: 3, transition: 'all 0.13s' }}>
      <span style={{ color: active ? '#818cf8' : '#64748b' }}>{icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, fontWeight: 500, color: active ? '#e2e8f0' : '#94a3b8', lineHeight: 1.3 }}>{label}</div>
        <div style={{ fontSize: 10, color: active ? '#6366f1' : '#64748b', marginTop: 1 }}>{sub}</div>
      </div>
      {badge && <span style={{ fontSize: 9, background: 'rgba(99,102,241,0.25)', color: '#818cf8', padding: '1px 5px', borderRadius: 4, fontWeight: 700 }}>{badge}</span>}
      {active && <ChevronRight size={12} color="#3d4451" />}
    </button>
  );
}

function Card({ children, style }) {
  return <div style={{ borderRadius: 12, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', ...style }}>{children}</div>;
}

function CardHeader({ children }) {
  return <div style={{ padding: '11px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 10, fontWeight: 600, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{children}</div>;
}

function Spinner() {
  return <>
    <style>{`@keyframes _sp { to { transform: rotate(360deg); } }`}</style>
    <div style={{ width: 36, height: 36, borderRadius: '50%', border: '2px solid rgba(99,102,241,0.18)', borderTop: '2px solid #6366f1', animation: '_sp 0.75s linear infinite' }} />
  </>;
}

// —�—�—� Markdown renderer (53) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

function MdText({ text }) {
  if (!text) return null;
  const lines = text.split('\n');
  const nodes = [];
  let inCode = false;
  let codeBuf = [];
  let codeLang = '';

  const renderInline = (str) => {
    // Patterns: bold **x**, code `x`, italic *x*, hex 0x⬦, dll/exe names, known protections
    const PROTECT_RE = /\b(Denuvo|VMProtect|Themida|UPX|MPRESS|Obsidium|ASPack|Enigma|Arxan|SafeDisc|SecuROM)\b/i;
    const HEX_RE     = /\b0x[0-9A-Fa-f]{2,}\b/;
    const DLL_RE     = /\b[\w-]+\.(dll|exe|sys|drv)\b/i;
    const parts = [];
    let rest = str;
    let key = 0;
    while (rest.length) {
      const boldM    = rest.match(/\*\*(.+?)\*\*/);
      const codeM    = rest.match(/`([^`]+)`/);
      const italM    = rest.match(/\*([^*]+)\*/);
      const hexM     = rest.match(HEX_RE);
      const dllM     = rest.match(DLL_RE);
      const protM    = rest.match(PROTECT_RE);
      const matches  = [boldM, codeM, italM, hexM, dllM, protM].filter(Boolean).sort((a, b) => a.index - b.index);
      if (!matches.length) { parts.push(<React.Fragment key={key++}>{rest}</React.Fragment>); break; }
      const m = matches[0];
      if (m.index > 0) parts.push(<React.Fragment key={key++}>{rest.slice(0, m.index)}</React.Fragment>);
      if (m === boldM)  parts.push(<strong key={key++} style={{ color: '#e2e8f0', fontWeight: 700 }}>{m[1]}</strong>);
      else if (m === codeM)  parts.push(<code key={key++} style={{ fontFamily: 'monospace', fontSize: '0.9em', padding: '1px 5px', borderRadius: 3, background: 'rgba(99,102,241,0.15)', color: '#c4b5fd' }}>{m[1]}</code>);
      else if (m === italM)  parts.push(<em key={key++} style={{ color: '#a78bfa', fontStyle: 'italic' }}>{m[1]}</em>);
      else if (m === hexM)   parts.push(<code key={key++} style={{ fontFamily: 'monospace', fontSize: '0.9em', padding: '1px 5px', borderRadius: 3, background: 'rgba(245,158,11,0.12)', color: '#fbbf24', fontWeight: 600 }}>{m[0]}</code>);
      else if (m === dllM)   parts.push(<code key={key++} style={{ fontFamily: 'monospace', fontSize: '0.9em', padding: '1px 5px', borderRadius: 3, background: 'rgba(34,197,94,0.09)', color: '#4ade80' }}>{m[0]}</code>);
      else if (m === protM)  parts.push(<span key={key++} style={{ padding: '1px 6px', borderRadius: 3, background: 'rgba(239,68,68,0.15)', color: '#f87171', fontWeight: 700, fontSize: '0.88em' }}>{m[0]}</span>);
      rest = rest.slice(m.index + m[0].length);
    }
    return parts;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('```')) {
      if (!inCode) { inCode = true; codeBuf = []; codeLang = line.slice(3).trim(); }
      else {
        nodes.push(
          <div key={i} style={{ margin: '8px 0', borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.08)' }}>
            {codeLang && <div style={{ padding: '3px 12px', background: 'rgba(99,102,241,0.12)', fontSize: 10, color: '#818cf8', fontWeight: 600 }}>{codeLang}</div>}
            <pre style={{ margin: 0, padding: '10px 14px', background: 'rgba(0,0,0,0.35)', fontSize: 11, color: '#94a3b8', fontFamily: 'monospace', overflowX: 'auto', lineHeight: 1.6 }}>{codeBuf.join('\n')}</pre>
          </div>
        );
        inCode = false; codeBuf = [];
      }
      continue;
    }
    if (inCode) { codeBuf.push(line); continue; }

    if (line.startsWith('### '))      nodes.push(<h3 key={i} style={{ margin: '14px 0 4px', fontSize: 13, fontWeight: 700, color: '#c4b5fd' }}>{renderInline(line.slice(4))}</h3>);
    else if (line.startsWith('## '))  nodes.push(<h2 key={i} style={{ margin: '18px 0 5px', fontSize: 15, fontWeight: 700, color: '#a78bfa', borderBottom: '1px solid rgba(139,92,246,0.2)', paddingBottom: 4 }}>{renderInline(line.slice(3))}</h2>);
    else if (line.startsWith('# '))   nodes.push(<h1 key={i} style={{ margin: '20px 0 6px', fontSize: 17, fontWeight: 800, color: '#818cf8' }}>{renderInline(line.slice(2))}</h1>);
    else if (/^[-*] /.test(line))     nodes.push(<div key={i} style={{ display: 'flex', gap: 7, margin: '3px 0', paddingLeft: 8 }}><span style={{ color: '#6366f1', flexShrink: 0, marginTop: 1 }}>⬺</span><span style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.65 }}>{renderInline(line.slice(2))}</span></div>);
    else if (/^\d+\. /.test(line)) {
      const dotIdx = line.indexOf('. ');
      nodes.push(<div key={i} style={{ display: 'flex', gap: 7, margin: '3px 0', paddingLeft: 8 }}><span style={{ color: '#6366f1', flexShrink: 0, fontWeight: 700, fontSize: 11 }}>{line.slice(0, dotIdx + 1)}</span><span style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.65 }}>{renderInline(line.slice(dotIdx + 2))}</span></div>);
    }
    else if (line.trim() === '')      nodes.push(<div key={i} style={{ height: 8 }} />);
    else                              nodes.push(<p key={i} style={{ margin: '4px 0', fontSize: 13, color: '#94a3b8', lineHeight: 1.7 }}>{renderInline(line)}</p>);
  }
  return <div>{nodes}</div>;
}

// —�—�—� Scanner Page —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

function ScannerPage({ onSendToAI, onSendToChat, onOpenDisasm }) {
  const [file, setFile]         = useState(null);
  const [result, setResult]     = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError]       = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [tab, setTab]           = useState('overview');
  const [strFilter, setStrFilter] = useState('');
  const [strCat, setStrCat]     = useState('all');
  const [showHistory, setShowHistory]     = useState(false);         // 22
  const [history, setHistory]             = useState(() => getHistory()); // 22
  const [histSearch, setHistSearch]       = useState('');            // 24 — history search
  const [editNoteId, setEditNoteId]       = useState(null);          // 25 — active note edit
  const [noteText, setNoteText]           = useState('');            // 25
  const [notes, setNotes]                 = useState(() => getNotes()); // 25
  const [multiResults, setMultiResults]   = useState([]);            // 01 — multi-file
  const [compareFile, setCompareFile]     = useState(null);          // 23
  const [compareResult, setCompareResult] = useState(null);          // 23
  const [comparingFile, setComparingFile] = useState(false);         // 23
  const [compareDragOver, setCompareDragOver] = useState(false);     // 23
  const [starred, setStarred]             = useState(() => getStarred()); // G4
  const [vtApiKey, setVtApiKey]           = useState(() => localStorage.getItem('dissect_vt_key') || ''); // E3
  const [vtResult, setVtResult]           = useState(null);          // E3
  const [vtLoading, setVtLoading]         = useState(false);         // E3
  const [scanFilePath, setScanFilePath]   = useState(null);          // A1 — native file path
  const [disasmResult, setDisasmResult]   = useState(null);          // A1
  const [disasmLoading, setDisasmLoading] = useState(false);         // A1
  const [scanRawBytes, setScanRawBytes]   = useState(null);          // B6 — first 8K bytes for hex diff
  const [compareRawBytes, setCompareRawBytes] = useState(null);      // B6
  const [upxResult, setUpxResult]         = useState(null);          // F2
  const [upxRunning, setUpxRunning]       = useState(false);         // F2
  const [dumpResult, setDumpResult]       = useState(null);          // F3
  const [dumpRunning, setDumpRunning]     = useState(false);         // F3
  const compareRef = useRef(null);
  const ref = useRef(null);
  const folderRef = useRef(null);  // 02 — folder scan

  // 01 — multi-file scan
  const processFiles = (files) => {
    if (!files || files.length === 0) return;
    if (files.length === 1) { processFile(files[0]); return; }
    setResult(null); setError(null); setCompareFile(null); setCompareResult(null);
    setMultiResults(Array.from(files).map(f => ({ name: f.name, size: f.size, status: 'pending', result: null })));
    setScanning(true);

    // FAZ 3.5 — use Rust parallel batch scanner if all files have native paths
    const fileArr = Array.from(files);
    const allPaths = fileArr.every(f => f.path);
    if (allPaths && window.__TAURI__) {
      (async () => {
        try {
          const paths = fileArr.map(f => f.path);
          const results = await invoke('batch_scan', { filePaths: paths });
          const mapped = fileArr.map((f, i) => {
            const r = results[i];
            if (r && r._status === 'ok') {
              addToHistory(f.name, r);
              return { name: f.name, size: f.size, status: 'done', result: r };
            } else {
              return { name: f.name, size: f.size, status: 'error', error: r?._error || 'Bilinmeyen hata' };
            }
          });
          setMultiResults(mapped);
          setHistory(getHistory());
        } catch (err) {
          console.warn('Batch scan failed, falling back to JS:', err);
          processFilesJS(fileArr);
          return;
        } finally { setScanning(false); }
      })();
      return;
    }
    processFilesJS(fileArr);
  };

  // JS fallback for multi-file scan
  const processFilesJS = (files) => {
    Array.from(files).forEach((f, idx) => {
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const r = await analyzePE(new Uint8Array(e.target.result));
          addToHistory(f.name, r);
          setMultiResults(prev => { const next = [...prev]; next[idx] = { ...next[idx], status: 'done', result: r }; return next; });
        } catch (err) {
          setMultiResults(prev => { const next = [...prev]; next[idx] = { ...next[idx], status: 'error', error: err.message }; return next; });
        } finally {
          setMultiResults(prev => {
            const allDone = prev.every(x => x.status !== 'pending');
            if (allDone) { setScanning(false); setHistory(getHistory()); }
            return prev;
          });
        }
      };
      reader.readAsArrayBuffer(f);
    });
  };

  const processFile = (f) => {
    if (!f) return;
    setFile(f); setResult(null); setError(null); setScanning(true); setTab('overview');
    setStrFilter(''); setStrCat('all');
    setCompareFile(null); setCompareResult(null); setMultiResults([]);
    setDisasmResult(null);
    // A1 — store native path if available (drag-drop in Tauri provides f.path)
    if (f.path) setScanFilePath(f.path); else setScanFilePath(null);

    // FAZ 3.1 — prefer Rust scanner when native path available
    if (f.path && window.__TAURI__) {
      (async () => {
        try {
          await new Promise(r => setTimeout(r, 200));
          const r = await invoke('scan_pe_full', { filePath: f.path });
          // Normalize string objects for frontend compat
          if (r.strings) r.strings = r.strings.map(s => typeof s === 'string' ? { text: s, cat: null } : { text: s.text, cat: s.cat });
          setResult(r);
          addToHistory(f.name, r);
          setHistory(getHistory());
          if (Notification.permission === 'granted') {
            new Notification('Dissect — Scan Complete', { body: `${f.name} · Risk ${r.riskScore} · ${r.riskScore >= 60 ? '⚡ HIGH RISK' : r.riskScore >= 30 ? 'MODERATE' : 'CLEAN'} (Rust ⚡)`, silent: true });
          }
          // Also read first 8K for hex view
          const reader2 = new FileReader();
          reader2.onload = (e2) => setScanRawBytes(new Uint8Array(e2.target.result).slice(0, 8192));
          reader2.readAsArrayBuffer(f);
        } catch (err) {
          // Fallback to JS scanner
          console.warn('Rust scanner failed, falling back to JS:', err);
          processFileJS(f);
        } finally { setScanning(false); }
      })();
      return;
    }
    processFileJS(f);
  };

  // JS fallback scanner
  const processFileJS = (f) => {
    setScanning(true);
    const reader = new FileReader();
    reader.onload = async (e) => {
      const arr = new Uint8Array(e.target.result);
      setScanRawBytes(arr.slice(0, 8192)); // B6 store first 8K
      try {
        await new Promise(r => setTimeout(r, 700));
        const r = await analyzePE(arr);
        setResult(r);
        addToHistory(f.name, r);                                   // 22 — auto-save
        setHistory(getHistory());
        // 50 — OS notification
        if (Notification.permission === 'granted') {
          new Notification('Dissect — Scan Complete', { body: `${f.name} · Risk ${r.riskScore} · ${r.riskScore >= 60 ? '⚡ HIGH RISK' : r.riskScore >= 30 ? 'MODERATE' : 'CLEAN'}`, silent: true });
        } else if (Notification.permission !== 'denied') {
          Notification.requestPermission();
        }

      } catch (err) { setError(err.message); }
      finally { setScanning(false); }
    };
    reader.readAsArrayBuffer(f);
  };

  // 23 — Process second (compare) file
  const processCompareFile = (f) => {
    if (!f) return;
    setCompareFile(f); setComparingFile(true); setCompareResult(null); setCompareRawBytes(null);
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const arr = new Uint8Array(e.target.result);
        setCompareRawBytes(arr.slice(0, 8192)); // B6
        const r = await analyzePE(arr);
        setCompareResult(r);
        setTab('compare');
      } catch (err) { setCompareResult({ error: err.message }); }
      finally { setComparingFile(false); }
    };
    reader.readAsArrayBuffer(f);
  };

  // 22 — JSON export of full history
  const exportHistory = () => {
    const blob = new Blob([JSON.stringify(getHistory(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `dissect_history_${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(a.href);
  };

  const risk   = result?.riskScore || 0;
  const rColor = risk >= 60 ? '#ef4444' : risk >= 30 ? '#f59e0b' : '#22c55e';
  const rLabel = risk >= 60 ? 'HIGH RISK' : risk >= 30 ? 'MODERATE' : 'CLEAN';

  const totalStrings  = result?.strings?.length || 0;
  const flaggedStrings = result?.strings?.filter(s => s.cat).length || 0;
  const yaraHits = result ? YARA_RULES.filter(r => { try { return r.match(result); } catch { return false; } }) : [];

  const TABS = [
    { id: 'overview',   label: 'Overview'  },
    { id: 'sections',   label: 'Sections'  },
    { id: 'strings',    label: `Strings (${totalStrings})`, badge: flaggedStrings > 0 ? flaggedStrings : null },
    { id: 'imports',    label: `Imports (${result?.imports?.length || 0})` },
    { id: 'exports',    label: `Exports (${result?.exports?.length || 0})` },
    { id: 'resources',  label: `Resources (B1)`, badge: result?.resources?.length > 0 ? result.resources.length : null },
    { id: 'yara',       label: `YARA`, badge: yaraHits.length > 0 ? yaraHits.length : null },
    { id: 'analyze',    label: 'Analyze' },
    { id: 'disasm',     label: 'Disasm (A1)' },
    ...(compareResult && !compareResult.error ? [{ id: 'compare', label: 'Diff ↓' }] : []),
  ];

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 22 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.13)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><ShieldAlert size={17} color="#818cf8" /></div>
            <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, color: '#f1f5f9' }}>Binary Scanner</h1>
          </div>
          <p style={{ fontSize: 12, color: '#374151', margin: 0 }}>PE header · Entropy · Import table · Anti-debug · Denuvo / VMProtect / Themida · String classification</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {/* 22 — History button */}
          <button onClick={() => setShowHistory(h => !h)}
            style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: `1px solid ${showHistory ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: showHistory ? 'rgba(99,102,241,0.12)' : 'transparent', color: showHistory ? '#818cf8' : '#374151', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
            <Layers size={13} /> Geçmiş {history.length > 0 && `(${history.length})`}
          </button>
          {result && (
            <button onClick={() => onSendToAI(result, file?.name)}
              style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Bot size={13} /> Send to AI
            </button>
          )}
          {result && (
            <button onClick={() => onSendToChat({ type: 'scanner', fileName: file?.name, data: result })}
              style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.07)', color: '#a78bfa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <MessageSquare size={13} /> Chat'e Gönder
            </button>
          )}
          {/* 38 — JSON report export */}
          {result && (
            <button onClick={() => {
              const blob = new Blob([JSON.stringify({ file: file?.name, size: file?.size, ...result }, null, 2)], { type: 'application/json' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_${(file?.name || 'scan').replace(/\.[^.]+$/, '')}_${Date.now()}.json`;
              a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> JSON
            </button>
          )}
          {/* E2 — STIX 2.1 export */}
          {result && (
            <button onClick={() => {
              const now = new Date().toISOString();
              const iocs = [];
              (result.strings || []).filter(s => s.cat === 'ip').forEach(s => iocs.push({ type: 'ipv4-addr', id: `ipv4-addr--${crypto.randomUUID?.() || Date.now()}`, value: s.text }));
              (result.strings || []).filter(s => s.cat === 'domain').forEach(s => iocs.push({ type: 'domain-name', id: `domain-name--${crypto.randomUUID?.() || Date.now()}`, value: s.text }));
              if (result.sha256) iocs.push({ type: 'file', id: `file--${crypto.randomUUID?.() || Date.now()}`, hashes: { 'SHA-256': result.sha256, 'SHA-1': result.sha1, 'MD5': result.md5 }, name: file?.name, size: file?.size });
              const bundle = {
                type: 'bundle', id: `bundle--${crypto.randomUUID?.() || Date.now()}`,
                spec_version: '2.1', created: now, modified: now,
                objects: [
                  { type: 'malware', spec_version: '2.1', id: `malware--${crypto.randomUUID?.() || Date.now()}`, created: now, modified: now, name: file?.name || 'unknown', malware_types: result.denuvo ? ['ransomware'] : ['unknown'], is_family: false,
                    custom_properties: { x_risk_score: result.riskScore, x_packers: result.packers, x_entropy: result.overallEntropy, x_arch: result.arch } },
                  ...iocs,
                ],
              };
              const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_stix_${Date.now()}.json`; a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.06)', color: '#fbbf24', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> STIX
            </button>
          )}
          {/* E5 — IOC CSV */}
          {result && (
            <button onClick={() => {
              const rows = [['type','value','category']];
              (result.strings || []).filter(s => s.cat).forEach(s => rows.push([s.cat, s.text, s.cat]));
              if (result.sha256) rows.push(['sha256', result.sha256, 'hash']);
              if (result.sha1)   rows.push(['sha1',   result.sha1,   'hash']);
              if (result.md5)    rows.push(['md5',    result.md5,    'hash']);
              const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
              const blob = new Blob([csv], { type: 'text/csv' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_ioc_${Date.now()}.csv`; a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.3)', background: 'rgba(96,165,250,0.06)', color: '#60a5fa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> IOC CSV
            </button>
          )}
          {/* E4 — Bulk report (all multi-scan results) */}
          {multiResults.length > 1 && (
            <button onClick={() => {
              const done = multiResults.filter(r => r.status === 'done');
              if (!done.length) return;
              const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Dissect Bulk Report</title><style>body{font-family:system-ui;background:#0d1117;color:#e2e8f0;padding:32px}h1{color:#818cf8}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #1f2937}th{background:#161b22;font-weight:600}tr:nth-child(even){background:#0d1117}tr:nth-child(odd){background:#090c12}.risk-hi{color:#f87171}.risk-md{color:#fbbf24}.risk-lo{color:#4ade80}</style></head><body><h1>Dissect Bulk Scan Report (E4)</h1><p style="color:#4b5563">${new Date().toLocaleString('tr-TR')} · ${done.length} files</p><table><thead><tr><th>File</th><th>Arch</th><th>Risk</th><th>Protections</th><th>SHA-256</th><th>Entropy</th><th>Sections</th></tr></thead><tbody>${done.map(({ name, result: r }) => `<tr><td>${name}</td><td>${r.arch}</td><td class="${r.riskScore >= 60 ? 'risk-hi' : r.riskScore >= 30 ? 'risk-md' : 'risk-lo'}">${r.riskScore}</td><td>${[r.denuvo&&'Denuvo',r.vmp&&'VMProtect',r.themida&&'Themida',r.antiDebug&&'Anti-Debug',r.antiVM&&'Anti-VM',...(r.packers||[])].filter(Boolean).join(', ')||'—'}</td><td style="font-family:monospace;font-size:10px">${r.sha256?.slice(0,16)+'⬦'||'—'}</td><td style="font-family:monospace">${r.overallEntropy?.toFixed(3)||'—'}</td><td>${r.numSec}</td></tr>`).join('')}</tbody></table></body></html>`;
              const blob = new Blob([html], { type: 'text/html' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_bulk_${Date.now()}.html`; a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(168,85,247,0.3)', background: 'rgba(168,85,247,0.06)', color: '#c084fc', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> Bulk Report
            </button>
          )}
          {file && !scanning && (
            <button onClick={() => { setFile(null); setResult(null); setError(null); setCompareFile(null); setCompareResult(null); }}
              style={{ fontSize: 11, padding: '5px 13px', borderRadius: 7, border: '1px solid rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.07)', color: '#f87171', cursor: 'pointer', fontWeight: 500 }}>
              Clear
            </button>
          )}
        </div>
      </div>

      {/* 22 — History panel (24 = search, 25 = notes) */}
      {showHistory && (
        <div style={{ borderRadius: 12, marginBottom: 16, background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(99,102,241,0.15)', overflow: 'hidden' }}>
          <div style={{ padding: '9px 14px', background: 'rgba(99,102,241,0.06)', borderBottom: '1px solid rgba(99,102,241,0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', textTransform: 'uppercase', letterSpacing: '0.07em', flexShrink: 0 }}>Tarama Geçmişi</span>
            {/* 24 — search */}
            <input value={histSearch} onChange={e => setHistSearch(e.target.value)} placeholder="Ara&"
              style={{ flex: 1, maxWidth: 180, fontSize: 10, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.07)', color: '#94a3b8', outline: 'none' }} />
            <div style={{ display: 'flex', gap: 8 }}>
              {history.length > 0 && <button onClick={exportHistory} style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer' }}>JSON Export</button>}
              {history.length > 0 && <button onClick={() => { localStorage.removeItem(HISTORY_KEY); setHistory([]); }} style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>Temizle</button>}
            </div>
          </div>
          {history.length === 0
            ? <div style={{ padding: '24px', textAlign: 'center', fontSize: 12, color: '#374151' }}>Henüz kayıtlı tarama yok</div>
            : <div style={{ maxHeight: 260, overflowY: 'auto' }}>
                {(() => {
                  const q = histSearch.toLowerCase();
                  const filtered = history.filter(h => !q
                    || h.fileName.toLowerCase().includes(q)
                    || String(h.riskScore).includes(q)
                    || h.arch?.toLowerCase().includes(q)
                    || (h.packers || []).some(p => p.toLowerCase().includes(q))
                    || (h.result?.sha256 || '').toLowerCase().includes(q)
                  );
                  // G4: starred first
                  const sorted = [...filtered.filter(h => starred.has(h.id)), ...filtered.filter(h => !starred.has(h.id))];
                  return sorted.map(h => {
                  const note = notes[h.id];
                  const isEditing = editNoteId === h.id;
                  const isStar = starred.has(h.id);
                  return (
                    <div key={h.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <div onClick={() => { if (!isEditing) { setResult(h.result); setFile({ name: h.fileName, size: 0 }); setTab('overview'); setShowHistory(false); } }}
                        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 14px', cursor: 'pointer', transition: 'background 0.12s' }}
                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        {/* G4 — star button */}
                        <button onClick={e => { e.stopPropagation(); setStarred(toggleStarred(h.id)); }}
                          title={isStar ? 'Y1ld1z1 kald1r' : 'Y1ld1zla'}
                          style={{ fontSize: 12, lineHeight: 1, background: 'transparent', border: 'none', cursor: 'pointer', color: isStar ? '#fbbf24' : '#2d3748', padding: 0, flexShrink: 0 }}>
                          {isStar ? '⭐' : '☆'}
                        </button>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: h.riskScore >= 60 ? '#ef4444' : h.riskScore >= 30 ? '#f59e0b' : '#22c55e', flexShrink: 0 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, color: isStar ? '#fef3c7' : '#94a3b8', fontWeight: isStar ? 600 : 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.fileName}</div>
                          <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{h.arch} · Risk {h.riskScore} · {new Date(h.ts).toLocaleString('tr-TR')}</div>
                          {note && !isEditing && <div style={{ fontSize: 10, color: '#a78bfa', marginTop: 2, fontStyle: 'italic' }}>✎ {note}</div>}
                        </div>
                        {/* 25 — note button */}
                        <button onClick={e => { e.stopPropagation(); setEditNoteId(isEditing ? null : h.id); setNoteText(note || ''); }}
                          style={{ fontSize: 10, padding: '2px 7px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.2)', background: isEditing ? 'rgba(139,92,246,0.1)' : 'transparent', color: '#a78bfa', cursor: 'pointer', flexShrink: 0 }}>
                          {isEditing ? '💾' : (note ? '✏️' : '+ Not')}
                        </button>
                        <span style={{ fontSize: 9, color: '#6b7280', fontFamily: 'monospace', flexShrink: 0 }}>Yükle →</span>
                      </div>
                      {/* 25 — inline note editor */}
                      {isEditing && (
                        <div style={{ padding: '0 14px 10px 32px', display: 'flex', gap: 6 }}>
                          <input autoFocus value={noteText} onChange={e => setNoteText(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') { saveNote(h.id, noteText); setNotes(getNotes()); setEditNoteId(null); } if (e.key === 'Escape') setEditNoteId(null); }}
                            placeholder="Not ekle⬦ (Enter = kaydet)"
                            style={{ flex: 1, fontSize: 11, padding: '4px 8px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(0,0,0,0.3)', color: '#c4b5fd', outline: 'none' }} />
                          <button onClick={() => { saveNote(h.id, noteText); setNotes(getNotes()); setEditNoteId(null); }}
                            style={{ fontSize: 10, padding: '4px 9px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.1)', color: '#a78bfa', cursor: 'pointer' }}>
                            Kaydet
                          </button>
                        </div>
                      )}
                    </div>
                  );
                  });})()} 
              </div>
          }
        </div>
      )}

      {/* Drop Zone — 01 multi-file */}
      {!result && !scanning && !error && multiResults.length === 0 && (
        <>
          {/* F4 — Scan Profiles */}
          {(() => {
            const PROFILES = [
              { id: 'quick',    label: '⚡ Quick',    desc: 'EP + protections + hash',     color: '#4ade80' },
              { id: 'deep',     label: '🔬 Deep',     desc: 'All sections + strings + IOC', color: '#60a5fa' },
              { id: 'forensic', label: '🧪 Forensic', desc: 'Full analysis + PDB + diff',   color: '#c084fc' },
            ];
            const [profile, setProfile] = React.useState(() => localStorage.getItem('dissect_profile') || 'deep');
            return (
              <div style={{ display: 'flex', gap: 6, marginBottom: 10, justifyContent: 'center' }}>
                {PROFILES.map(p => (
                  <button key={p.id} onClick={() => { setProfile(p.id); localStorage.setItem('dissect_profile', p.id); }}
                    title={p.desc}
                    style={{ fontSize: 11, padding: '5px 14px', borderRadius: 8, border: `1px solid ${profile === p.id ? p.color + '44' : 'rgba(255,255,255,0.06)'}`, background: profile === p.id ? p.color + '12' : 'transparent', color: profile === p.id ? p.color : '#374151', cursor: 'pointer', fontWeight: profile === p.id ? 600 : 400, transition: 'all 0.15s' }}>
                    {p.label}
                  </button>
                ))}
                <span style={{ fontSize: 10, color: '#2d3748', alignSelf: 'center', marginLeft: 6 }}>{PROFILES.find(p => p.id === profile)?.desc}</span>
              </div>
            );
          })()}
        <div onClick={() => ref.current.click()} onDrop={(e) => { e.preventDefault(); setDragOver(false); processFiles(e.dataTransfer.files); }} onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
          style={{ borderRadius: 16, border: `2px dashed ${dragOver ? '#6366f1' : 'rgba(99,102,241,0.22)'}`, background: dragOver ? 'rgba(99,102,241,0.07)' : 'rgba(99,102,241,0.02)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 280, cursor: 'pointer', transition: 'all 0.18s' }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(99,102,241,0.45)'; e.currentTarget.style.background = 'rgba(99,102,241,0.04)'; }}
          onMouseLeave={e => { if (!dragOver) { e.currentTarget.style.borderColor = 'rgba(99,102,241,0.22)'; e.currentTarget.style.background = 'rgba(99,102,241,0.02)'; }}}>
          <div style={{ width: 58, height: 58, borderRadius: 16, background: 'rgba(99,102,241,0.11)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 18 }}><FileSearch size={28} color="#6366f1" /></div>
          <div style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 7 }}>Drop a binary or click to browse</div>
          <div style={{ fontSize: 12, color: '#2d3748' }}>.exe · .dll · .sys — Multiple files · Drag a folder to scan all binaries</div>
          {/* 02 — folder scan button */}
          <div style={{ display: 'flex', gap: 10, marginTop: 14 }} onClick={e => e.stopPropagation()}>
            <button onClick={() => ref.current.click()}
              style={{ fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer' }}>
              Files
            </button>
            <button onClick={() => folderRef.current.click()}
              style={{ fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#6366f1', cursor: 'pointer' }}>
              📁 Folder Scan
            </button>
          </div>
          <input ref={ref} type="file" multiple onChange={e => processFiles(e.target.files)} style={{ display: 'none' }} />
          <input ref={folderRef} type="file" multiple webkitdirectory="" onChange={e => {
            const files = Array.from(e.target.files).filter(f => /\.(exe|dll|sys|ocx|scr|cpl)$/i.test(f.name));
            if (files.length > 0) processFiles(files);
          }} style={{ display: 'none' }} />
        </div>
        </>
      )}

      {/* 01 — Multi-file results grid */}
      {multiResults.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#94a3b8' }}>Toplu Tarama — {multiResults.length} dosya</span>
            <button onClick={() => { setMultiResults([]); setScanning(false); }}
              style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>Temizle</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 10 }}>
            {multiResults.map((item, i) => {
              const rc = item.result?.riskScore >= 60 ? '#ef4444' : item.result?.riskScore >= 30 ? '#f59e0b' : '#22c55e';
              return (
                <div key={i} onClick={() => item.status === 'done' && (setFile({ name: item.name, size: item.size }), setResult(item.result), setTab('overview'), setMultiResults([]))}
                  style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.25)', border: `1px solid ${item.status === 'done' ? 'rgba(99,102,241,0.18)' : item.status === 'error' ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'}`, cursor: item.status === 'done' ? 'pointer' : 'default', transition: 'border-color 0.15s' }}
                  onMouseEnter={e => item.status === 'done' && (e.currentTarget.style.borderColor = 'rgba(99,102,241,0.4)')}
                  onMouseLeave={e => item.status === 'done' && (e.currentTarget.style.borderColor = 'rgba(99,102,241,0.18)')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    {item.status === 'pending' && <Spinner />}
                    {item.status === 'done'    && <div style={{ width: 8, height: 8, borderRadius: '50%', background: rc, boxShadow: `0 0 6px ${rc}66` }} />}
                    {item.status === 'error'   && <AlertTriangle size={12} color="#f87171" />}
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.name}</div>
                  </div>
                  {item.status === 'done' && (
                    <div style={{ fontSize: 10, color: '#374151' }}>
                      Risk <span style={{ color: rc, fontWeight: 700 }}>{item.result.riskScore}</span> · {item.result.arch} · {(item.size / 1024).toFixed(0)} KB
                      {item.result.packers?.length > 0 && <span style={{ color: '#fbbf24', marginLeft: 6 }}>{item.result.packers[0]}</span>}
                    </div>
                  )}
                  {item.status === 'error'   && <div style={{ fontSize: 10, color: '#f87171' }}>{item.error}</div>}
                  {item.status === 'done'    && <div style={{ fontSize: 9, color: '#374151', marginTop: 4 }}>Detay için tıkla →</div>}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Scanning */}
      {scanning && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 280, gap: 18 }}>
          <Spinner />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Analyzing {file?.name}</div>
            <div style={{ fontSize: 11, color: '#2d3748', marginTop: 5 }}>Parsing PE headers · Computing entropy · Scanning signatures · Extracting strings</div>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ borderRadius: 12, padding: '14px 16px', background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}><AlertTriangle size={15} color="#f87171" /><span style={{ fontSize: 13, color: '#f87171', fontWeight: 600 }}>Analysis Failed</span></div>
          <div style={{ fontSize: 12, color: '#6b7280' }}>{error}</div>
          <button onClick={() => { setFile(null); setError(null); }} style={{ marginTop: 10, fontSize: 11, padding: '5px 12px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>Try Again</button>
        </div>
      )}

      {/* Results */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

          {/* Risk Banner */}
          <div style={{ borderRadius: 12, padding: '14px 18px', background: `${rColor}0d`, border: `1px solid ${rColor}2e`, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 13 }}>
              <div style={{ width: 42, height: 42, borderRadius: 11, background: `${rColor}1a`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                {risk >= 30 ? <AlertTriangle size={20} color={rColor} /> : <ShieldCheck size={20} color={rColor} />}
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: rColor }}>{rLabel}</div>
                <div style={{ fontSize: 11, color: '#4b5563', marginTop: 3, fontFamily: 'monospace' }}>
                  {[result.denuvo && 'Denuvo', result.vmp && 'VMProtect', result.themida && 'Themida', result.antiDebug && 'Anti-Debug', result.antiVM && 'Anti-VM'].filter(Boolean).join(' · ') || 'No major protection'}
                  {result.suspiciousCount > 0 && ` · ${result.suspiciousCount} suspicious section${result.suspiciousCount > 1 ? 's' : ''}`}
                </div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 30, fontWeight: 800, color: rColor, lineHeight: 1 }}>{result.riskScore}</div>
              <div style={{ fontSize: 9, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 2 }}>Risk Score</div>
            </div>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 2, borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 0 }}>
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{ padding: '7px 14px', fontSize: 12, fontWeight: 500, border: 'none', cursor: 'pointer', background: 'transparent', borderBottom: `2px solid ${tab === t.id ? '#6366f1' : 'transparent'}`, color: tab === t.id ? '#818cf8' : '#374151', transition: 'all 0.13s', marginBottom: -1, display: 'flex', alignItems: 'center', gap: 5 }}>
                {t.label}
                {t.badge && <span style={{ fontSize: 9, background: 'rgba(239,68,68,0.2)', color: '#f87171', padding: '1px 5px', borderRadius: 4, fontWeight: 700 }}>{t.badge}</span>}
              </button>
            ))}
          </div>

          {/* Overview tab */}
          {tab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 260px', gap: 14 }}>
              {/* File info */}
              <Card>
                <CardHeader>File Info</CardHeader>
                <div style={{ padding: '4px 16px 12px' }}>
                  {[
                    { label: 'File Name',     value: file?.name,                                       trunc: true },
                    { label: 'Size',          value: `${(file?.size / 1048576).toFixed(2)} MB`         },
                    { label: 'Architecture',  value: result.arch + (result.isDll ? ' · DLL' : ' · EXE'), accent: true },
                    { label: 'Entry Point',   value: `0x${result.ep.toString(16).toUpperCase()}`,       mono: true, accent: true },
                    { label: 'Compiled',      value: result.compiledAt ? new Date(result.compiledAt).toLocaleDateString('tr-TR') + (result.fakeTimestamp ? ' ⚠ Sahte' : '') : '—', warn: result.fakeTimestamp },
                    { label: '.NET / CLR',    value: result.isDotNet ? 'YES — managed code' : 'No',    accent: result.isDotNet, warn: false },
                    { label: 'Overlay',       value: result.overlaySize > 0 ? `${(result.overlaySize / 1024).toFixed(1)} KB ⚡` : 'None', danger: result.overlaySize > 0 },
                    { label: 'Sections',      value: result.numSec                                      },
                    { label: 'Overall Entropy', value: `${result.overallEntropy.toFixed(4)} H`,         mono: true, warn: result.overallEntropy > 7 },
                    { label: 'Suspicious',    value: result.suspiciousCount,                            danger: result.suspiciousCount > 0 },
                    { label: 'Strings Found', value: result.strings.length                              },
                    { label: 'Flagged Strings', value: flaggedStrings,                                   danger: flaggedStrings > 0 },
                    { label: 'Imports (DLLs)',  value: result.imports?.length || 0,                     accent: true },
                    { label: 'Exports',         value: result.exports?.length || 0,                     accent: result.exports?.length > 0 },
                    { label: 'SHA-256',         value: result.sha256 ? result.sha256.slice(0,16)+'⬦' : '—', mono: true, title: result.sha256 || undefined },
                    { label: 'SHA-1',           value: result.sha1   ? result.sha1.slice(0,16)+'⬦'   : '—', mono: true, title: result.sha1   || undefined },
                    { label: 'MD5 (F5)',        value: result.md5    ? result.md5.slice(0,16)+'⬦'    : '—', mono: true, title: result.md5    || undefined },
                    { label: 'CRC32 (F5)',      value: result.crc32 || '—', mono: true },
                    { label: 'Imphash',         value: result.imphash ? result.imphash.slice(0,16)+'⬦' : '—', mono: true, title: result.imphash || undefined },
                    { label: 'Rich Header',     value: result.richHash ? result.richHash.slice(0,36)+'⬦' : 'Not found', mono: !!result.richHash, title: result.richHash || undefined, accent: !!result.richHash },
                    { label: 'PDB Path (B8)',   value: result.debugPdb || '—', mono: true, accent: !!result.debugPdb, title: result.debugPdb || undefined },
                  ].map(({ label, value, mono, trunc, accent, danger, warn, title }) => (
                    <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ fontSize: 11, color: '#374151' }}>{label}</span>
                      <span title={title} style={{ fontSize: 11, fontFamily: mono ? 'monospace' : 'inherit', fontWeight: 500, color: danger ? '#f87171' : warn ? '#f59e0b' : accent ? '#818cf8' : '#94a3b8', maxWidth: trunc ? 160 : undefined, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </Card>

              {/* E3 — VirusTotal hash sorgulama */}
              {result.sha256 && (
                <Card>
                  <CardHeader>VirusTotal Sorgula (E3)</CardHeader>
                  <div style={{ padding: '10px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ display: 'flex', gap: 7 }}>
                      <input value={vtApiKey} onChange={e => { setVtApiKey(e.target.value); localStorage.setItem('dissect_vt_key', e.target.value); }}
                        placeholder="VirusTotal API Key (ücretsiz key: virustotal.com/gui/my-apikey)"
                        type="password"
                        style={{ flex: 1, fontSize: 11, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(0,0,0,0.3)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                      <button disabled={!vtApiKey.trim() || vtLoading} onClick={async () => {
                        setVtLoading(true); setVtResult(null);
                        try {
                          const res = await fetch(`https://www.virustotal.com/api/v3/files/${result.sha256}`, { headers: { 'x-apikey': vtApiKey } });
                          const json = await res.json();
                          if (json.error) { setVtResult({ error: json.error.message }); }
                          else {
                            const a = json.data?.attributes;
                            setVtResult({ malicious: a?.last_analysis_stats?.malicious || 0, undetected: a?.last_analysis_stats?.undetected || 0, total: Object.values(a?.last_analysis_stats || {}).reduce((s, v) => s + v, 0), names: a?.names?.slice(0, 5) || [], firstSeen: a?.first_submission_date ? new Date(a.first_submission_date * 1000).toLocaleDateString('tr-TR') : null, permalink: `https://www.virustotal.com/gui/file/${result.sha256}` });
                          }
                        } catch (e) { setVtResult({ error: String(e) }); }
                        finally { setVtLoading(false); }
                      }} style={{ fontSize: 11, padding: '5px 14px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: vtApiKey.trim() && !vtLoading ? 'pointer' : 'not-allowed', fontWeight: 600, whiteSpace: 'nowrap', opacity: vtApiKey.trim() && !vtLoading ? 1 : 0.5 }}>
                        {vtLoading ? '⬦' : '🔍 Sorgula'}
                      </button>
                    </div>
                    {vtResult && (vtResult.error
                      ? <div style={{ fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>Hata: {vtResult.error}</div>
                      : <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: vtResult.malicious > 0 ? '#f87171' : '#4ade80' }}>{vtResult.malicious}/{vtResult.total} tespit</span>
                          {vtResult.malicious > 0 && <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)', fontWeight: 700 }}>MALICIOUS</span>}
                          {vtResult.firstSeen && <span style={{ fontSize: 10, color: '#374151' }}>İlk: {vtResult.firstSeen}</span>}
                          {vtResult.names?.length > 0 && <span style={{ fontSize: 10, color: '#374151' }}>{vtResult.names.join(', ')}</span>}
                          <a href={vtResult.permalink} target="_blank" rel="noreferrer" style={{ fontSize: 10, color: '#818cf8', marginLeft: 'auto' }}>VT'de aç  ?</a>
                        </div>
                    )}
                  </div>
                </Card>
              )}

              {/* Protection layers + 41 — Ordered analysis suggestions */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card>
                  <CardHeader>Protection Layers</CardHeader>
                  <div style={{ padding: '4px 16px 12px' }}>
                    {[
                      { name: 'Denuvo',     detected: result.denuvo,    desc: 'Anti-tamper · Online DRM' },
                      { name: 'VMProtect',  detected: result.vmp,       desc: 'Code virtualization' },
                      { name: 'Themida',    detected: result.themida,   desc: 'Anti-dump · Obfuscation' },
                      { name: 'Anti-Debug', detected: result.antiDebug, desc: 'IsDebuggerPresent / NtQuery⬦' },
                      { name: 'Anti-VM',    detected: result.antiVM,    desc: 'VMware / VBox / sandbox checks' },
                    ].map(({ name, detected, desc }) => (
                      <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        {detected ? <XCircle size={15} color="#ef4444" /> : <CheckCircle2 size={15} color="#22c55e" />}
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: detected ? '#f87171' : '#374151' }}>{name}</div>
                          <div style={{ fontSize: 10, color: '#2d3748' }}>{desc}</div>
                        </div>
                        <span style={{ fontSize: 10, fontWeight: 700, color: detected ? '#f87171' : '#22c55e' }}>{detected ? 'FOUND' : 'CLEAN'}</span>
                      </div>
                    ))}
                    {/* 16 — Detected packers */}
                    {result.packers?.length > 0 && (
                      <div style={{ paddingTop: 10, marginTop: 4 }}>
                        <div style={{ fontSize: 10, color: '#374151', marginBottom: 7, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Detected Packers</div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {result.packers.map(p => (
                            <span key={p} style={{ padding: '2px 9px', borderRadius: 5, background: 'rgba(251,191,36,0.12)', color: '#fbbf24', fontSize: 11, fontWeight: 700, border: '1px solid rgba(251,191,36,0.25)' }}>{p}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>

                {/* 41 — Ordered analysis recommendations */}
                {(() => {
                  const steps = [];
                  if (result.packers?.length > 0 || result.overallEntropy > 7.2)
                    steps.push({ n: 1, label: 'Unpack first', detail: 'High entropy / packer detected — unpack before analysis', col: '#f87171' });
                  if (result.antiDebug)
                    steps.push({ n: steps.length + 1, label: 'Bypass anti-debug', detail: 'Patch IsDebuggerPresent / NtQueryInformationProcess checks', col: '#fb923c' });
                  if (result.antiVM)
                    steps.push({ n: steps.length + 1, label: 'Remove VM checks', detail: 'VMware/VBox registry and process name queries detected', col: '#fb923c' });
                  if (result.denuvo || result.themida || result.vmp)
                    steps.push({ n: steps.length + 1, label: 'Handle DRM layer', detail: [result.denuvo && 'Denuvo', result.vmp && 'VMProtect', result.themida && 'Themida'].filter(Boolean).join(' + '), col: '#fbbf24' });
                  if (result.overlaySize > 0)
                    steps.push({ n: steps.length + 1, label: 'Inspect overlay', detail: `${(result.overlaySize / 1024).toFixed(1)} KB after last section — may contain payload`, col: '#fbbf24' });
                  const injStrings = result.strings?.filter(s => s.cat?.cat === 'injection') || [];
                  if (injStrings.length > 0)
                    steps.push({ n: steps.length + 1, label: 'Trace injection', detail: `${injStrings.length} injection API pattern(s) in strings`, col: '#f59e0b' });
                  if (result.imports?.length > 0)
                    steps.push({ n: steps.length + 1, label: 'Audit import table', detail: `${result.imports.length} DLL(s) — check for suspicious functions`, col: '#6366f1' });
                  if (result.strings?.some(s => s.cat?.cat === 'url' || s.cat?.cat === 'ip'))
                    steps.push({ n: steps.length + 1, label: 'Investigate network IOCs', detail: 'URLs and/or IPs found in strings — trace callbacks', col: '#818cf8' });
                  if (steps.length === 0)
                    steps.push({ n: 1, label: 'No major threats detected', detail: 'File appears clean — proceed with standard review', col: '#22c55e' });
                  return (
                    <Card>
                      <CardHeader>İnceleme Sırası (41)</CardHeader>
                      <div style={{ padding: '4px 16px 12px' }}>
                        {steps.map(({ n, label, detail, col }) => (
                          <div key={n} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                            <div style={{ width: 18, height: 18, borderRadius: '50%', background: `${col}22`, border: `1px solid ${col}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                              <span style={{ fontSize: 9, fontWeight: 700, color: col }}>{n}</span>
                            </div>
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 600, color: col }}>{label}</div>
                              <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{detail}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </Card>
                  );
                })()}
              </div>
            </div>
          )}

          {/* Sections tab — 47: entropy bar chart */}
          {tab === 'sections' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Bar chart */}
              <Card>
                <CardHeader>Entropy Chart — sections</CardHeader>
                <div style={{ padding: '14px 16px 4px', position: 'relative', display: 'flex', alignItems: 'flex-end', gap: 8, minHeight: 90 }}>
                  {/* 11 — 7.2 H danger threshold line */}
                  <div style={{ position: 'absolute', left: 16, right: 16, bottom: `calc(4px + ${(7.2/8)*60}px)`, height: 1, background: 'rgba(239,68,68,0.35)', zIndex: 1, pointerEvents: 'none' }}>
                    <span style={{ position: 'absolute', right: 0, top: -10, fontSize: 8, color: '#ef4444', opacity: 0.7 }}>7.2H</span>
                  </div>
                  {result.sections.map((sec, i) => {
                    const pct  = (sec.entropy / 8) * 100;
                    const col  = sec.entropy > 7.2 ? '#ef4444' : sec.entropy > 6.5 ? '#f59e0b' : '#6366f1';
                    return (
                      <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1, gap: 5 }}>
                        <span style={{ fontSize: 9, color: col, fontFamily: 'monospace', fontWeight: 700 }}>{sec.entropy.toFixed(2)}</span>
                        <div style={{ width: '100%', height: 60, background: 'rgba(255,255,255,0.04)', borderRadius: 4, display: 'flex', alignItems: 'flex-end', overflow: 'hidden' }}>
                          <div style={{ width: '100%', height: `${pct}%`, background: col, transition: 'height 0.8s ease', opacity: 0.85 }} />
                        </div>
                        <span style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace', maxWidth: 40, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>{sec.name}</span>
                      </div>
                    );
                  })}
                </div>
                {/* 11 — stats row */}
                <div style={{ padding: '4px 16px 8px', display: 'flex', gap: 16 }}>
                  {(() => {
                    const ents = result.sections.map(s => s.entropy);
                    const avg = ents.reduce((a,b) => a+b, 0) / (ents.length || 1);
                    const max = Math.max(...ents);
                    const hi  = ents.filter(e => e > 7.2).length;
                    return [
                      ['Avg', avg.toFixed(2)+'H', avg > 6.5 ? '#f59e0b' : '#374151'],
                      ['Max', max.toFixed(2)+'H', max > 7.2 ? '#ef4444' : '#374151'],
                      ['High-entropy sections', hi, hi > 0 ? '#ef4444' : '#374151'],
                    ].map(([l, v, c]) => (
                      <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{ fontSize: 9, color: '#2d3748' }}>{l}</span>
                        <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: c }}>{v}</span>
                      </div>
                    ));
                  })()}
                </div>
                <div style={{ padding: '0 16px 10px', display: 'flex', gap: 14 }}>
                  {[['#4ade80','< 6.5 H Normal'], ['#6366f1','6.5–7.2 H Elevated'], ['#f59e0b','7.2–7.5 H High'], ['#ef4444','> 7.5 H Packed/Encrypted']].map(([c,l]) => (
                    <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: c }} />
                      <span style={{ fontSize: 10, color: '#374151' }}>{l}</span>
                    </div>
                  ))}
                </div>
              </Card>

              {/* Section list */}
              <Card>
                <CardHeader>
                  PE Sections ({result.sections.length}) &nbsp;·&nbsp;
                  <span style={{ color: '#4b5563', textTransform: 'none', fontWeight: 400 }}>Overall entropy: </span>
                  <span style={{ color: result.overallEntropy > 7.0 ? '#f59e0b' : '#4b5563', fontFamily: 'monospace' }}>{result.overallEntropy.toFixed(3)} H</span>
                </CardHeader>
                {result.sections.map((sec, i) => (
                  <div key={i} style={{ padding: '10px 16px', borderBottom: i < result.sections.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none', background: sec.suspicious ? 'rgba(239,68,68,0.03)' : 'transparent' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 7 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700, padding: '2px 7px', borderRadius: 4, background: sec.suspicious ? 'rgba(239,68,68,0.13)' : 'rgba(99,102,241,0.1)', color: sec.suspicious ? '#f87171' : '#818cf8' }}>{sec.name}</span>
                        <span style={{ fontSize: 10, color: '#2d3748', fontFamily: 'monospace' }}>0x{sec.vaddr.toString(16).toUpperCase().padStart(8, '0')}</span>
                        {sec.isExec && <span style={{ fontSize: 9, color: '#4b5563', background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>EXEC</span>}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {sec.suspicious && <AlertTriangle size={11} color="#f59e0b" />}
                        <span style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 700, color: sec.entropy > 7.2 ? '#f87171' : sec.entropy > 6.5 ? '#f59e0b' : '#4ade80' }}>{sec.entropy.toFixed(3)} H</span>
                        <span style={{ fontSize: 10, color: '#2d3748', fontFamily: 'monospace' }}>{(sec.rsize / 1024).toFixed(0)} KB</span>
                      </div>
                    </div>
                    <div style={{ height: 3, borderRadius: 2, background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', borderRadius: 2, width: `${(sec.entropy / 8) * 100}%`, background: sec.entropy > 7.2 ? 'linear-gradient(90deg,#f59e0b,#ef4444)' : sec.entropy > 6.0 ? '#6366f1' : '#22c55e', transition: 'width 0.7s ease' }} />
                    </div>
                  </div>
                ))}
              </Card>
            </div>
          )}

          {/* Strings tab — 48: filter + category */}
          {tab === 'strings' && (() => {
            const cats = ['all', ...STR_PATTERNS.map(p => p.cat)];
            const filtered = result.strings.filter(s => {
              const matchCat = strCat === 'all' || s.cat?.cat === strCat;
              const matchTxt = !strFilter || s.text.toLowerCase().includes(strFilter.toLowerCase());
              return matchCat && matchTxt;
            });
            return (
              <Card>
                <CardHeader>
                  Strings — {filtered.length} / {totalStrings} &nbsp;·&nbsp;
                  <span style={{ color: '#f87171', textTransform: 'none', fontWeight: 400 }}>{flaggedStrings} flagged</span>
                </CardHeader>
                {/* Controls */}
                <div style={{ padding: '10px 12px 6px', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <input value={strFilter} onChange={e => setStrFilter(e.target.value)} placeholder="Filter strings⬦"
                    style={{ flex: 1, minWidth: 140, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6, padding: '5px 9px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                  {cats.map(c => {
                    const pat = STR_PATTERNS.find(p => p.cat === c);
                    const cnt = c === 'all' ? totalStrings : result.strings.filter(s => s.cat?.cat === c).length;
                    if (c !== 'all' && cnt === 0) return null;
                    return (
                      <button key={c} onClick={() => setStrCat(c)}
                        style={{ padding: '3px 9px', borderRadius: 5, border: `1px solid ${strCat === c ? (pat?.color || '#818cf8') : 'rgba(255,255,255,0.07)'}`, background: strCat === c ? `${pat?.color || '#818cf8'}18` : 'transparent', color: strCat === c ? (pat?.color || '#818cf8') : '#374151', cursor: 'pointer', fontSize: 10, fontWeight: strCat === c ? 700 : 400 }}>
                        {pat?.label || 'All'} {cnt > 0 && <span style={{ opacity: 0.7 }}>({cnt})</span>}
                      </button>
                    );
                  })}
                </div>
                <div style={{ padding: 12, maxHeight: 400, overflowY: 'auto', display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {filtered.slice(0, 400).map((s, i) => (
                    <span key={i} onClick={() => setStrFilter(s.text === strFilter ? '' : s.text)} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, background: s.cat ? `${s.cat.color}18` : 'rgba(255,255,255,0.04)', color: s.cat ? s.cat.color : '#6b7280', border: s.cat ? `1px solid ${s.cat.color}33` : '1px solid transparent', maxWidth: 340, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }} title={s.text}>{s.text}</span>
                  ))}
                  {filtered.length === 0 && <span style={{ fontSize: 12, color: '#374151' }}>No strings match the filter.</span>}
                </div>
                {/* A6 — String Cross-Reference: find import functions matching current filter */}
                {strFilter && (() => {
                  const q = strFilter.toLowerCase();
                  const refs = [];
                  (result.imports || []).forEach(imp => {
                    imp.funcs.filter(fn => fn.toLowerCase().includes(q)).forEach(fn => refs.push({ dll: imp.dll, fn }));
                  });
                  if (!refs.length) return null;
                  return (
                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', padding: '8px 12px' }}>
                      <div style={{ fontSize: 9, fontWeight: 700, color: '#818cf8', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 5 }}>String Cross-Reference (A6) — Import hits for "{strFilter}"</div>
                      {refs.map((r, i) => (
                        <div key={i} style={{ fontSize: 11, fontFamily: 'monospace', color: '#94a3b8', padding: '2px 0' }}>
                          <span style={{ color: '#6366f1' }}>{r.dll}</span> → <span style={{ color: '#60a5fa' }}>{r.fn}</span>
                        </div>
                      ))}
                    </div>
                  );
                })()}
              </Card>
            );
          })()}

          {/* Imports tab — 03: Import Table */}
          {tab === 'imports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* 26 — Dependency map */}
              {result.imports && result.imports.length > 0 && (
                <Card>
                  <CardHeader>Dependency Map — {result.imports.length} DLL{result.imports.length !== 1 ? 's' : ''}</CardHeader>
                  <div style={{ padding: '10px 16px 14px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                      {/* root node */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingBottom: 6 }}>
                        <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Binary size={14} color="#818cf8" /></div>
                        <span style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 700, color: '#818cf8' }}>{file?.name || 'target.exe'}</span>
                      </div>
                      {result.imports.map((imp, i) => {
                        const isLast = i === result.imports.length - 1;
                        const isSystemDll = /^(kernel32|ntdll|user32|gdi32|advapi32|msvcrt|ole32|shell32|ws2_32|wininet|urlmon)/i.test(imp.dll);
                        const isDanger   = imp.funcs.some(fn => /VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThread|LoadLibrary/i.test(fn));
                        const col = isDanger ? '#f87171' : isSystemDll ? '#374151' : '#94a3b8';
                        return (
                          <div key={i} style={{ display: 'flex', gap: 0 }}>
                            <div style={{ width: 14, flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                              <div style={{ width: 1, flex: 1, background: 'rgba(99,102,241,0.2)' }} />
                              {!isLast && <div style={{ width: 1, flex: 1, background: 'rgba(99,102,241,0.2)' }} />}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingBottom: isLast ? 0 : 4, paddingLeft: 8 }}>
                              <div style={{ width: 8, height: 1, background: 'rgba(99,102,241,0.3)', flexShrink: 0 }} />
                              <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 5, background: isDanger ? 'rgba(239,68,68,0.07)' : 'rgba(255,255,255,0.03)', border: `1px solid ${isDanger ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'}` }}>
                                <span style={{ fontSize: 11, fontFamily: 'monospace', color: col }}>{imp.dll}</span>
                                <span style={{ fontSize: 9, color: '#374151' }}>{imp.funcs.length}f</span>
                                {isDanger && <AlertTriangle size={9} color="#f87171" />}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </Card>
              )}
              <Card>
              <CardHeader>Import Table — {result.imports?.length || 0} DLLs</CardHeader>
              {(!result.imports || result.imports.length === 0) && (
                <div style={{ padding: 20, fontSize: 12, color: '#374151', textAlign: 'center' }}>No imports found or import directory not parseable.</div>
              )}
              <div style={{ maxHeight: 520, overflowY: 'auto' }}>
                {result.imports?.map((imp, i) => (
                  <div key={i} style={{ borderBottom: i < result.imports.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                    <div style={{ padding: '9px 16px 5px', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Layers size={12} color="#6366f1" style={{ flexShrink: 0 }} />
                      <span style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 700, color: '#818cf8' }}>{imp.dll}</span>
                      <span style={{ fontSize: 10, color: '#374151', marginLeft: 'auto' }}>{imp.funcs.length} func{imp.funcs.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div style={{ padding: '2px 16px 10px', display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {imp.funcs.slice(0, 60).map((fn, j) => {
                        const isAntiDebug = STR_PATTERNS.find(p => p.cat === 'antidebug')?.re.test(fn);
                        const isNetwork   = STR_PATTERNS.find(p => p.cat === 'network')?.re.test(fn);
                        const isCrypto    = STR_PATTERNS.find(p => p.cat === 'crypto')?.re.test(fn);
                        const col = isAntiDebug ? '#f87171' : isNetwork ? '#34d399' : isCrypto ? '#fbbf24' : '#4b5563';
                        return (
                          <span key={j} style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3, background: 'rgba(255,255,255,0.03)', color: col, border: '1px solid rgba(255,255,255,0.04)' }}>{fn}</span>
                        );
                      })}
                      {imp.funcs.length > 60 && <span style={{ fontSize: 10, color: '#374151' }}>+{imp.funcs.length - 60} more⬦</span>}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
            </div>
          )}

          {/* Exports tab — 04 */}
          {tab === 'exports' && (
            <Card>
              <CardHeader>Export Table — {result.exports?.length || 0} function{result.exports?.length !== 1 ? 's' : ''}</CardHeader>
              {(!result.exports || result.exports.length === 0)
                ? <div style={{ padding: 24, textAlign: 'center', fontSize: 12, color: '#374151' }}>No exports found — this is likely an EXE rather than a DLL.</div>
                : (
                  <div style={{ maxHeight: 520, overflowY: 'auto' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.06em', padding: '7px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <span>Function Name</span><span style={{ marginRight: 24 }}>Ordinal</span><span>RVA</span>
                    </div>
                    {result.exports.map((ex, i) => (
                      <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', padding: '6px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)', alignItems: 'center' }}>
                        <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ex.name || `(unnamed)`}</span>
                        <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#4b5563', marginRight: 24 }}>#{ex.ordinal}</span>
                        <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6366f1' }}>{ex.rva}</span>
                      </div>
                    ))}
                  </div>
                )
              }
            </Card>
          )}

          {/* B1 — Resources tab */}
          {tab === 'resources' && (
            <Card>
              <CardHeader>PE Resources (B1) — {result.resources?.length || 0} resource types</CardHeader>
              {(!result.resources || result.resources.length === 0) && (
                <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 12, color: '#374151' }}>
                  No resource directory found, or resource section could not be parsed.<br />
                  <span style={{ fontSize: 10, color: '#1f2937' }}>This is normal for many command-line executables.</span>
                </div>
              )}
              {result.resources && result.resources.length > 0 && (
                <div style={{ padding: '8px 16px 14px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8, marginBottom: 12 }}>
                    {result.resources.map((r, i) => {
                      const ICONS = { Icon: '🖼', Bitmap: '🖼', Manifest: '📋', VersionInfo: '✎', String: '✎', Menu: '☰', Dialog: '💬', Cursor: '🖼', RCData: '✎' };
                      const ic = ICONS[r.name] || '✎';
                      return (
                        <div key={i} style={{ padding: '10px 14px', borderRadius: 9, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.14)', display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{ fontSize: 20 }}>{ic}</span>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 600, color: '#818cf8' }}>{r.name}</div>
                            <div style={{ fontSize: 10, color: '#4b5563' }}>Type {r.type} · {r.count} item{r.count !== 1 ? 's' : ''}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {result.resources.some(r => r.name === 'VersionInfo') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '8px 0' }}>
                      📋 <strong style={{ color: '#818cf8' }}>VersionInfo</strong> resource detected — may contain product name, version, company, copyright strings.
                    </div>
                  )}
                  {result.resources.some(r => r.name === 'Manifest') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '4px 0' }}>
                      📋 <strong style={{ color: '#60a5fa' }}>Manifest</strong> resource detected — may contain requested execution level, DPI settings, dependencies.
                    </div>
                  )}
                </div>
              )}
            </Card>
          )}

          {/* B1 — Resources tab */}
          {tab === 'resources' && (
            <Card>
              <CardHeader>PE Resources (B1) — {result.resources?.length || 0} resource types</CardHeader>
              {(!result.resources || result.resources.length === 0) && (
                <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 12, color: '#374151' }}>
                  No resource directory found, or resource section could not be parsed.<br />
                  <span style={{ fontSize: 10, color: '#1f2937' }}>This is normal for many command-line executables.</span>
                </div>
              )}
              {result.resources && result.resources.length > 0 && (
                <div style={{ padding: '8px 16px 14px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8, marginBottom: 12 }}>
                    {result.resources.map((r, i) => {
                      const ICONS = { Icon: '🖼', Bitmap: '🖼', Manifest: '📋', VersionInfo: '✎', String: '✎', Menu: '☰', Dialog: '💬', Cursor: '🖼', RCData: '✎' };
                      const ic = ICONS[r.name] || '✎';
                      return (
                        <div key={i} style={{ padding: '10px 14px', borderRadius: 9, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.14)', display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{ fontSize: 20 }}>{ic}</span>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 600, color: '#818cf8' }}>{r.name}</div>
                            <div style={{ fontSize: 10, color: '#4b5563' }}>Type {r.type} · {r.count} item{r.count !== 1 ? 's' : ''}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {result.resources.some(r => r.name === 'VersionInfo') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '8px 0' }}>
                      📋 <strong style={{ color: '#818cf8' }}>VersionInfo</strong> resource detected — may contain product name, version, company, copyright strings.
                    </div>
                  )}
                  {result.resources.some(r => r.name === 'Manifest') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '4px 0' }}>
                      📋 <strong style={{ color: '#60a5fa' }}>Manifest</strong> resource detected — may contain requested execution level, DPI settings, dependencies.
                    </div>
                  )}
                </div>
              )}
            </Card>
          )}

          {/* YARA tab — 12 */}
          {tab === 'yara' && (
            <Card>
              <CardHeader>YARA-like Rule Engine — {yaraHits.length} kural eşleşti / {YARA_RULES.length} kural</CardHeader>
              <div style={{ padding: '8px 16px 12px' }}>
                {YARA_RULES.map(rule => {
                  let hit = false;
                  try { hit = rule.match(result); } catch {}
                  const col = YARA_SEV_COLOR[rule.sev] || '#6b7280';
                  const desc = typeof rule.desc === 'function' ? rule.desc(result) : rule.desc;
                  return (
                    <div key={rule.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', opacity: hit ? 1 : 0.35 }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', background: hit ? col : '#1e2330', flexShrink: 0, boxShadow: hit ? `0 0 6px ${col}66` : 'none' }} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 12, fontWeight: hit ? 600 : 400, color: hit ? col : '#374151' }}>{rule.name}</div>
                        {hit && desc && <div style={{ fontSize: 10, color: '#6b7280', marginTop: 2 }}>{desc}</div>}
                      </div>
                      <span style={{ fontSize: 9, padding: '1px 7px', borderRadius: 4, background: hit ? `${col}18` : 'rgba(255,255,255,0.03)', color: hit ? col : '#2d3748', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        {hit ? rule.sev : 'clean'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          {/* —�—� Analyze tab — A3/A4/A5/B5/B7 —�—� */}
          {tab === 'analyze' && (() => {
            // A3 — minimal x86/x64 byte description helper
            const descByte = (bytes, i) => {
              const b = bytes[i] ? parseInt(bytes[i], 16) : null;
              if (b === null) return { mnem: '??', bytes: 1 };
              const ops = {
                0x90: { mnem: 'NOP', bytes: 1 },
                0xCC: { mnem: 'INT3', bytes: 1 },
                0xC3: { mnem: 'RETN', bytes: 1 },
                0xC2: { mnem: `RETN ${parseInt(bytes[i+1]||'0',16)+(parseInt(bytes[i+2]||'0',16)<<8)}`, bytes: 3 },
                0xEB: { mnem: `JMP SHORT +0x${bytes[i+1]||'00'}`, bytes: 2 },
                0xE9: { mnem: `JMP [→ ${bytes.slice(i+1,i+5).reverse().join('')}]`, bytes: 5 },
                0xE8: { mnem: `CALL [→ ${bytes.slice(i+1,i+5).reverse().join('')}]`, bytes: 5 },
                0x55: { mnem: 'PUSH EBP/RBP', bytes: 1 },
                0x53: { mnem: 'PUSH EBX', bytes: 1 },
                0x56: { mnem: 'PUSH ESI', bytes: 1 },
                0x57: { mnem: 'PUSH EDI', bytes: 1 },
                0x5D: { mnem: 'POP EBP', bytes: 1 }, 0x5B: { mnem: 'POP EBX', bytes: 1 },
                0x6A: { mnem: `PUSH ${bytes[i+1]||'??'}`, bytes: 2 },
                0x68: { mnem: `PUSH DWORD [${bytes.slice(i+1,i+5).join(' ')}]`, bytes: 5 },
                0x8B: { mnem: 'MOV r, r/m', bytes: 2 },
                0x89: { mnem: 'MOV r/m, r', bytes: 2 },
                0x8D: { mnem: 'LEA r, m', bytes: 2 },
                0x83: { mnem: 'OP r/m, imm8', bytes: 3 },
                0x81: { mnem: 'OP r/m, imm32', bytes: 6 },
                0x85: { mnem: 'TEST r/m, r', bytes: 2 },
                0x31: { mnem: 'XOR r/m, r', bytes: 2 },
                0x33: { mnem: 'XOR r, r/m', bytes: 2 },
                0x01: { mnem: 'ADD r/m, r', bytes: 2 },
                0x03: { mnem: 'ADD r, r/m', bytes: 2 },
                0x29: { mnem: 'SUB r/m, r', bytes: 2 },
                0x2B: { mnem: 'SUB r, r/m', bytes: 2 },
                0xFF: { mnem: 'CALL/JMP/INC/DEC r/m', bytes: 2 },
                0x50: { mnem: 'PUSH EAX/RAX', bytes: 1 }, 0x51: { mnem: 'PUSH ECX', bytes: 1 },
                0x52: { mnem: 'PUSH EDX', bytes: 1 }, 0x58: { mnem: 'POP EAX', bytes: 1 },
                0x74: { mnem: `JZ +${bytes[i+1]||'00'}h`, bytes: 2 }, 0x75: { mnem: `JNZ +${bytes[i+1]||'00'}h`, bytes: 2 },
                0x72: { mnem: `JB +${bytes[i+1]||'00'}h`, bytes: 2 }, 0x73: { mnem: `JAE +${bytes[i+1]||'00'}h`, bytes: 2 },
                0xF3: { mnem: 'REP prefix', bytes: 1 }, 0xF2: { mnem: 'REPNE prefix', bytes: 1 },
                0x48: { mnem: bytes[i+1] ? 'REX.W prefix' : 'DEC EAX', bytes: 1 },
                0x40: { mnem: 'INC EAX / REX', bytes: 1 },
                0x0F: { mnem: `0F ${bytes[i+1]||'?'} (ext)`, bytes: 2 },
              };
              return ops[b] || { mnem: `db ${bytes[i]}`, bytes: 1 };
            };
            const epRows = [];
            const byts = result.epBytes || [];
            let off = 0;
            while (off < Math.min(byts.length, 64)) {
              const d = descByte(byts, off);
              epRows.push({ off, hex: byts.slice(off, off + d.bytes).join(' '), mnem: d.mnem, bytes: d.bytes });
              off += d.bytes || 1;
            }
            // A5 state via local component isn't possible here inline — use controlled input in closure
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

                {/* A3 — EP disassembly */}
                <Card>
                  <CardHeader>Entry Point Disassembly — EP RVA: 0x{result.ep?.toString(16).toUpperCase().padStart(8,'0')} · File Offset: 0x{result.epFileOff?.toString(16).toUpperCase().padStart(8,'0')}</CardHeader>
                  <div style={{ padding: '8px 0 10px', fontFamily: 'monospace' }}>
                    {byts.length === 0
                      ? <div style={{ padding: '8px 16px', fontSize: 11, color: '#374151' }}>EP baytları yüklenemedi (packed/overlay EP olabilir)</div>
                      : epRows.map((r, i) => (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '80px 140px 1fr', padding: '2px 16px', fontSize: 11, background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                          <span style={{ color: '#4b5563' }}>+0x{r.off.toString(16).padStart(4,'0')}</span>
                          <span style={{ color: '#374151' }}>{r.hex}</span>
                          <span style={{ color: r.mnem.startsWith('db') ? '#6b7280' : r.mnem.includes('CALL') || r.mnem.includes('JMP') ? '#60a5fa' : r.mnem === 'NOP' ? '#4b5563' : r.mnem.includes('PUSH') || r.mnem.includes('POP') ? '#c4b5fd' : '#94a3b8' }}>{r.mnem}</span>
                        </div>
                      ))
                    }
                    {byts.length > 0 && <div style={{ padding: '6px 16px 0', fontSize: 10, color: '#1f2937' }}>Showing first ~64 bytes at EP. JMP/CALL targets are relative offsets only.</div>}
                  </div>
                </Card>

                {/* A5 — RVA  — File Offset calculator */}
                {(() => {
                  const [rvaIn, setRvaIn] = React.useState('');
                  const [calcResult, setCalcResult] = React.useState(null);
                  const calcRva = () => {
                    const n = parseInt(rvaIn, 16) || parseInt(rvaIn, 10) || 0;
                    const secs = result.sections || [];
                    const match = secs.find(s => n >= s.vaddr && n < s.vaddr + (s.vsize || s.rsize));
                    if (match) {
                      const fileOff = (match.rawOff || 0) + (n - match.vaddr);
                      setCalcResult({ rva: `0x${n.toString(16).toUpperCase().padStart(8,'0')}`, fileOff: `0x${fileOff.toString(16).toUpperCase().padStart(8,'0')}`, section: match.name });
                    } else {
                      setCalcResult({ error: `RVA 0x${n.toString(16).toUpperCase()} herhangi bir section içinde de?il` });
                    }
                  };
                  return (
                    <Card>
                      <CardHeader>RVA / VA → File Offset Calculator (A5)</CardHeader>
                      <div style={{ padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                        <input value={rvaIn} onChange={e => setRvaIn(e.target.value)} placeholder="RVA veya VA (hex: 0x... veya decimal)"
                          style={{ flex: 1, minWidth: 220, fontSize: 12, padding: '6px 10px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.05)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }}
                          onKeyDown={e => e.key === 'Enter' && calcRva()} />
                        <button onClick={calcRva} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer' }}>Hesapla</button>
                        {calcResult && !calcResult.error && (
                          <div style={{ display: 'flex', gap: 16, fontSize: 11, fontFamily: 'monospace', flexWrap: 'wrap' }}>
                            <span style={{ color: '#374151' }}>RVA: <span style={{ color: '#6366f1' }}>{calcResult.rva}</span></span>
                            <span style={{ color: '#374151' }}>File Offset: <span style={{ color: '#4ade80' }}>{calcResult.fileOff}</span></span>
                            <span style={{ color: '#374151' }}>Section: <span style={{ color: '#94a3b8' }}>{calcResult.section}</span></span>
                          </div>
                        )}
                        {calcResult?.error && <span style={{ fontSize: 11, color: '#f87171' }}>{calcResult.error}</span>}
                      </div>
                      <div style={{ padding: '0 16px 10px', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {(result.sections || []).map(s => (
                          <div key={s.name} onClick={() => { setRvaIn(`0x${s.vaddr.toString(16).toUpperCase()}`); }}
                            style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)', color: '#4b5563', cursor: 'pointer', fontFamily: 'monospace' }}>
                            {s.name} VA=0x{s.vaddr.toString(16).toUpperCase().padStart(8,'0')}
                          </div>
                        ))}
                      </div>
                    </Card>
                  );
                })()}

                {/* A4 — Code caves */}
                <Card>
                  <CardHeader>Code Cave Tespiti — {result.codeCaves?.length || 0} boş bölge (exec section'larda ≥16 byte 0x00)</CardHeader>
                  <div style={{ padding: '8px 0 10px' }}>
                    {(!result.codeCaves || result.codeCaves.length === 0)
                      ? <div style={{ padding: '6px 16px', fontSize: 11, color: '#374151' }}>Anlamlı code cave bulunamadı.</div>
                      : result.codeCaves.map((c, i) => (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '80px 130px 1fr', padding: '5px 16px', borderBottom: '1px solid rgba(255,255,255,0.03)', alignItems: 'center' }}>
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6366f1' }}>0x{c.fileOff.toString(16).toUpperCase().padStart(8,'0')}</span>
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: c.size >= 128 ? '#4ade80' : '#f59e0b' }}>{c.size} bytes</span>
                          <span style={{ fontSize: 10, color: '#374151' }}>{c.section}</span>
                        </div>
                      ))
                    }
                  </div>
                </Card>

                {/* B5 — WRX sections */}
                {result.wrxSections?.length > 0 && (
                  <Card>
                    <CardHeader style={{ color: '#f87171' }}>⚡ Writeable + Executable Sections (B5)</CardHeader>
                    <div style={{ padding: '8px 16px 12px' }}>
                      <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 8 }}>W+X flag kombinasyonu — inject/shellcode barındırma riski</div>
                      {result.wrxSections.map(s => (
                        <span key={s} style={{ display: 'inline-block', marginRight: 8, marginBottom: 4, fontSize: 11, padding: '2px 10px', borderRadius: 5, background: 'rgba(239,68,68,0.12)', color: '#f87171', fontFamily: 'monospace', border: '1px solid rgba(239,68,68,0.2)' }}>{s}</span>
                      ))}
                    </div>
                  </Card>
                )}

                {/* B7 — Packing ratios */}
                <Card>
                  <CardHeader>Packing Ratios — raw/virtual size oranı</CardHeader>
                  <div style={{ padding: '6px 0 10px' }}>
                    {(result.packingRatios || []).map((s, i) => {
                      const r = parseFloat(s.ratio) || 0;
                      const col = r < 0.3 ? '#ef4444' : r < 0.7 ? '#f59e0b' : '#4ade80';
                      return (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '90px 90px 90px 1fr', padding: '5px 16px', borderBottom: '1px solid rgba(255,255,255,0.03)', alignItems: 'center', fontSize: 11 }}>
                          <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{s.name}</span>
                          <span style={{ fontFamily: 'monospace', color: '#4b5563' }}>{(s.raw/1024).toFixed(1)}K raw</span>
                          <span style={{ fontFamily: 'monospace', color: '#374151' }}>{(s.virt/1024).toFixed(1)}K virt</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <div style={{ flex: 1, height: 5, borderRadius: 3, background: 'rgba(255,255,255,0.04)', overflow: 'hidden' }}>
                              <div style={{ width: `${Math.min(100, r * 100)}%`, height: '100%', background: col, transition: 'width 0.5s' }} />
                            </div>
                            <span style={{ fontSize: 10, fontFamily: 'monospace', color: col }}>{s.ratio}</span>
                            {r < 0.3 && <span style={{ fontSize: 9, color: '#ef4444' }}>PACKED?</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>

                {/* F2 — Multi-Packer Unpack (FAZ 3.2) */}
                {result.packers?.length > 0 || result.sections?.some(s => /^(\.upx|\.aspack|\.mpress|\.petite|\.pec|nsp|\.te!|\.exec|enigma)/i.test(s.name)) ? (
                  <Card>
                    <CardHeader>Packer Detected (FAZ 3.2) — {result.packers?.join(', ') || 'Unknown'} — Unpack</CardHeader>
                    <div style={{ padding: '12px 16px' }}>
                      <div style={{ fontSize: 12, color: '#f59e0b', marginBottom: 10 }}>
                        Packed executable detected. Click to attempt automatic decompression (UPX/ASPack/MPRESS/PECompact/Petite support).
                      </div>
                      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                        <button disabled={upxRunning || !scanFilePath} onClick={async () => {
                          if (!scanFilePath) return;
                          setUpxRunning(true); setUpxResult(null);
                          try { const r = await invoke('try_unpack', { filePath: scanFilePath }); setUpxResult(r); }
                          catch (e) { setUpxResult({ ok: false, msg: String(e) }); }
                          finally { setUpxRunning(false); }
                        }} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.35)', background: upxRunning ? 'transparent' : 'rgba(245,158,11,0.08)', color: '#fbbf24', cursor: scanFilePath ? 'pointer' : 'not-allowed', opacity: scanFilePath ? 1 : 0.5, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
                          {upxRunning ? <><Spinner /> Unpacking...</> : '⚡ Auto-Unpack'}
                        </button>
                        {!scanFilePath && <span style={{ fontSize: 10, color: '#4b5563' }}>Requires native file path (drag & drop file)</span>}
                      </div>
                      {upxResult && (
                        <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 7, background: upxResult.ok ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)', border: `1px solid ${upxResult.ok ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}` }}>
                          <div style={{ fontSize: 11, color: upxResult.ok ? '#4ade80' : '#f87171', marginBottom: 4 }}>{upxResult.ok ? '✅ Unpacked successfully' : '❌ Unpack failed'}</div>
                          {upxResult.method && <div style={{ fontSize: 10, color: '#6366f1', marginBottom: 4 }}>Method: {upxResult.method}</div>}
                          {upxResult.detected_packers?.length > 0 && <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Detected: {upxResult.detected_packers.join(', ')}</div>}
                          {upxResult.suggestion && <div style={{ fontSize: 10, color: '#f59e0b', marginBottom: 4 }}>💡 {upxResult.suggestion}</div>}
                          <pre style={{ fontSize: 10, color: '#6b7280', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{upxResult.msg}</pre>
                        </div>
                      )}
                    </div>
                  </Card>
                ) : null}

                {/* F3 — Enhanced Memory Dump Analysis (FAZ 3.3) */}
                {(() => {
                  const isDump = file?.name?.match(/\.(dmp|dump|mem|bin|raw)$/i) || (result.overallEntropy > 5.0 && !result.isPe);
                  if (!isDump) return null;
                  return (
                    <Card>
                      <CardHeader>Memory Dump / Raw Binary Analysis (FAZ 3.3)</CardHeader>
                      <div style={{ padding: '12px 16px' }}>
                        <div style={{ fontSize: 12, color: '#60a5fa', marginBottom: 10 }}>
                          Detected memory dump or raw binary. Deep analysis: MDMP parsing, embedded PE search, entropy mapping, region enumeration, and PE extraction.
                        </div>
                        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: dumpResult ? 12 : 0 }}>
                          <button disabled={dumpRunning || !scanFilePath} onClick={async () => {
                            if (!scanFilePath) return;
                            setDumpRunning(true); setDumpResult(null);
                            try { const r = await invoke('analyze_dump_enhanced', { filePath: scanFilePath }); setDumpResult(r); }
                            catch (e) { setDumpResult({ error: String(e) }); }
                            finally { setDumpRunning(false); }
                          }} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.35)', background: dumpRunning ? 'transparent' : 'rgba(96,165,250,0.08)', color: '#60a5fa', cursor: scanFilePath ? 'pointer' : 'not-allowed', opacity: scanFilePath ? 1 : 0.5, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
                            {dumpRunning ? <><Spinner /> Analyzing...</> : '🔬 Enhanced Dump Analysis'}
                          </button>
                          {!scanFilePath && <span style={{ fontSize: 10, color: '#4b5563' }}>Requires native file path (drag & drop)</span>}
                        </div>
                        {dumpResult && !dumpResult.error && (
                          <div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8, marginBottom: 10 }}>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>File Size</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: '#818cf8', fontFamily: 'monospace' }}>{(dumpResult.size / 1024 / 1024).toFixed(2)} MB</div>
                              </div>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>Entropy</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: dumpResult.entropy > 7.5 ? '#f87171' : dumpResult.entropy > 6.5 ? '#f59e0b' : '#4ade80', fontFamily: 'monospace' }}>{dumpResult.entropy?.toFixed(3)}</div>
                              </div>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>Embedded PEs</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: (dumpResult.pe_count || dumpResult.pe_offsets?.length) > 0 ? '#f59e0b' : '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.pe_count || dumpResult.pe_offsets?.length || 0}</div>
                              </div>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>Format</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: dumpResult.is_minidump ? '#f59e0b' : '#4ade80' }}>{dumpResult.is_minidump ? 'MDMP' : dumpResult.is_likely_dump ? 'Raw Dump' : 'Binary'}</div>
                              </div>
                            </div>

                            {/* MDMP info */}
                            {dumpResult.is_minidump && dumpResult.dump_info && (
                              <div style={{ marginBottom: 10, padding: '8px 12px', borderRadius: 7, background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.15)' }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#fbbf24', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Windows Minidump Header</div>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6, fontSize: 10 }}>
                                  <div><span style={{ color: '#4b5563' }}>Version:</span> <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.dump_info.version}</span></div>
                                  <div><span style={{ color: '#4b5563' }}>Streams:</span> <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.dump_info.num_streams}</span></div>
                                  <div><span style={{ color: '#4b5563' }}>Timestamp:</span> <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.dump_info.timestamp}</span></div>
                                </div>
                                {dumpResult.dump_info.streams?.length > 0 && (
                                  <div style={{ marginTop: 6, maxHeight: 100, overflowY: 'auto' }}>
                                    {dumpResult.dump_info.streams.map((s, i) => (
                                      <div key={i} style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace', padding: '1px 0' }}>
                                        [{s.type}] {s.name} — {s.size} bytes @ 0x{Number(s.offset).toString(16).toUpperCase()}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Embedded PE images with extraction */}
                            {dumpResult.pe_images?.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Embedded PE Images ({dumpResult.pe_images.length})</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                  {dumpResult.pe_images.map((pe, i) => (
                                    <div key={i} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)' }}>
                                      <span style={{ fontFamily: 'monospace', color: '#fbbf24' }}>{pe.offset}</span>
                                      <span style={{ color: '#4b5563', marginLeft: 6 }}>{pe.arch} · {pe.sections} sections · {(pe.estimated_size/1024).toFixed(1)}KB</span>
                                      {pe.can_extract && <span style={{ color: '#4ade80', marginLeft: 6 }}>✓ extractable</span>}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Fallback: legacy pe_offsets */}
                            {!dumpResult.pe_images && dumpResult.pe_offsets?.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>MZ Headers at offsets</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                  {dumpResult.pe_offsets.map((off, i) => (
                                    <span key={i} style={{ fontSize: 11, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 5, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', color: '#fbbf24' }}>
                                      0x{Number(off).toString(16).toUpperCase().padStart(8, '0')}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Memory regions */}
                            {dumpResult.memory_regions?.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Memory Regions ({dumpResult.memory_regions.length})</div>
                                <div style={{ maxHeight: 150, overflowY: 'auto', fontSize: 10, fontFamily: 'monospace' }}>
                                  {dumpResult.memory_regions.map((r, i) => (
                                    <div key={i} style={{ display: 'grid', gridTemplateColumns: '90px 90px 80px 70px 1fr', padding: '2px 0', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                                      <span style={{ color: '#6366f1' }}>{r.start}</span>
                                      <span style={{ color: '#4b5563' }}>{r.end}</span>
                                      <span style={{ color: '#94a3b8' }}>{(r.size/1024).toFixed(1)}K</span>
                                      <span style={{ color: r.entropy > 7 ? '#f87171' : r.entropy > 5 ? '#f59e0b' : '#4ade80' }}>{r.entropy}</span>
                                      <span style={{ color: '#374151' }}>{r.type}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {dumpResult.strings_sample?.length > 0 && (
                              <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>String Sample ({dumpResult.strings_sample.length} of up to 100)</div>
                                <div style={{ maxHeight: 160, overflowY: 'auto', fontFamily: 'monospace', fontSize: 10, color: '#374151', background: 'rgba(0,0,0,0.25)', borderRadius: 6, padding: '6px 10px', lineHeight: 1.7 }}>
                                  {dumpResult.strings_sample.map((s, i) => <div key={i}>{s}</div>)}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                        {dumpResult?.error && <div style={{ fontSize: 11, color: '#f87171', marginTop: 8 }}>{dumpResult.error}</div>}
                      </div>
                    </Card>
                  );
                })()}

                {/* FAZ 3.1 — YARA Rule Matches (from Rust scanner) */}
                {result.yaraMatches?.length > 0 && (
                  <Card>
                    <CardHeader>YARA-like Rules — {result.yaraMatches.length} match</CardHeader>
                    <div style={{ padding: '8px 0 10px' }}>
                      {result.yaraMatches.map((m, i) => {
                        const cols = { critical: '#ef4444', high: '#f59e0b', medium: '#60a5fa', warn: '#fbbf24', low: '#94a3b8' };
                        const col = cols[m.sev] || '#94a3b8';
                        return (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 16px', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                            <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${col}22`, color: col, fontWeight: 700, textTransform: 'uppercase', minWidth: 52, textAlign: 'center' }}>{m.sev}</span>
                            <span style={{ fontSize: 11, color: '#e5e7eb', fontWeight: 600 }}>{m.name}</span>
                            {m.desc && <span style={{ fontSize: 10, color: '#4b5563', marginLeft: 'auto' }}>{m.desc}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </Card>
                )}

                {/* FAZ 3.4 — Fuzzy Hash (ssdeep-style) */}
                {scanFilePath && window.__TAURI__ && (
                  <Card>
                    <CardHeader>Fuzzy Hash — CTPH (FAZ 3.4)</CardHeader>
                    <div style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
                        <button onClick={async () => {
                          try {
                            const r = await invoke('fuzzy_hash', { filePath: scanFilePath });
                            setResult(prev => ({ ...prev, fuzzyHash: r.fuzzy_hash, fuzzyBlockSize: r.block_size }));
                          } catch (e) { console.error('fuzzy_hash error', e); }
                        }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(168,85,247,0.35)', background: 'rgba(168,85,247,0.08)', color: '#a855f7', cursor: 'pointer', fontWeight: 500 }}>
                          🔑 Generate Fuzzy Hash
                        </button>
                        {result.fuzzyHash && (
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#94a3b8', wordBreak: 'break-all' }}>{result.fuzzyHash}</span>
                        )}
                      </div>
                      {result.fuzzyHash && (
                        <div style={{ fontSize: 10, color: '#4b5563' }}>Block size: {result.fuzzyBlockSize} — Compare with another file's fuzzy hash for similarity detection</div>
                      )}
                    </div>
                  </Card>
                )}

                {/* FAZ 3.1 — Scanner badge */}
                {result._scanner === 'rust' && (
                  <div style={{ padding: '6px 16px', fontSize: 10, color: '#4b5563', textAlign: 'right' }}>
                    ⚡ Scanned by Rust backend{result._format ? ` · ${result._format}` : ' · PE'}{result.fileSize ? ` · ${(result.fileSize/1024).toFixed(1)} KB` : ''}
                  </div>
                )}

              </div>
            );
          })()}
          {tab === 'disasm' && (() => {
            const loadDisasm = async () => {
              if (!scanFilePath) return;
              setDisasmLoading(true);
              try {
                const r = await invoke('disassemble_ep', { filePath: scanFilePath, count: 80 });
                setDisasmResult(r);
              } catch (e) { setDisasmResult({ error: e }); }
              finally { setDisasmLoading(false); }
            };
            if (!disasmResult && !disasmLoading && scanFilePath) loadDisasm();
            const kindColor = { call: '#60a5fa', jmp: '#f59e0b', ret: '#f87171', '': '#94a3b8' };
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card>
                  <CardHeader>Disassembly — Entry Point (A1/A2) · {result?.arch}</CardHeader>
                  {scanFilePath && (
                    <div style={{ padding: '8px 16px 0', display: 'flex', justifyContent: 'flex-end' }}>
                      <button onClick={() => onOpenDisasm && onOpenDisasm(scanFilePath)}
                        style={{ fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
                        <Code size={12} /> Tam Disassembly Görünümü →
                      </button>
                    </div>
                  )}
                  {!scanFilePath && (
                    <div style={{ padding: 16, fontSize: 12, color: '#374151' }}>
                      📌 Disassembly requires the native file path. Drag & drop the file onto Dissect to enable this feature.
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Raw EP Bytes (from JS analysis)</div>
                        <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#374151', wordBreak: 'break-all', lineHeight: 2 }}>
                          {(result.epBytes || []).slice(0, 64).join(' ')}
                        </div>
                      </div>
                    </div>
                  )}
                  {scanFilePath && disasmLoading && <div style={{ padding: 24, display: 'flex', justifyContent: 'center' }}><Spinner /></div>}
                  {scanFilePath && !disasmLoading && disasmResult && !disasmResult.error && (
                    <div style={{ fontFamily: 'monospace', overflowX: 'auto' }}>
                      {/* A2 — Mark basic block boundaries */}
                      {disasmResult.map((ins, i) => {
                        const isBlockEnd = ins.kind === 'ret' || ins.kind === 'jmp';
                        return (
                          <div key={i} style={{ display: 'grid', gridTemplateColumns: '110px 160px 80px 1fr', padding: '3px 16px', fontSize: 11, background: isBlockEnd ? 'rgba(99,102,241,0.04)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)', borderBottom: isBlockEnd ? '1px solid rgba(99,102,241,0.1)' : undefined }}>
                            <span style={{ color: '#4b5563', userSelect: 'text' }}>{ins.addr}</span>
                            <span style={{ color: '#1f2937', userSelect: 'text' }}>{ins.bytes}</span>
                            <span style={{ color: kindColor[ins.kind] || '#94a3b8', fontWeight: 600, userSelect: 'text' }}>{ins.mnemonic}</span>
                            <span style={{ color: '#4b5563', userSelect: 'text' }}>{ins.operands}</span>
                          </div>
                        );
                      })}
                      <div style={{ padding: '8px 16px', fontSize: 10, color: '#1f2937' }}>
                        {disasmResult.length} instructions · CALL=<span style={{ color: '#60a5fa' }}>blue</span> · JMP=<span style={{ color: '#f59e0b' }}>amber</span> · RET=<span style={{ color: '#f87171' }}>red</span> · Block boundaries marked
                      </div>
                    </div>
                  )}
                  {scanFilePath && !disasmLoading && disasmResult?.error && (
                    <div style={{ padding: 16, color: '#f87171', fontSize: 12 }}>Hata: {String(disasmResult.error)}</div>
                  )}
                  {scanFilePath && !disasmLoading && !disasmResult && (
                    <button onClick={loadDisasm} style={{ margin: 16, fontSize: 12, padding: '8px 18px', borderRadius: 8, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.07)', color: '#818cf8', cursor: 'pointer' }}>
                      Disassemble EP
                    </button>
                  )}
                </Card>
                {/* B2/B3/B4/B8 advanced PE info */}
                <Card>
                  <CardHeader>Advanced PE Fields (B2/B3/B4/B8)</CardHeader>
                  <div style={{ padding: '10px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {[
                      { label: 'TLS Section (B2)', value: result.hasTls ? '✅ PRESENT (.tls detected)' : '— Not found', color: result.hasTls ? '#fbbf24' : '#374151' },
                      { label: 'Exception Entries (B3)', value: result.exceptionEntries > 0 ? `${result.exceptionEntries} RUNTIME_FUNCTION entries in .pdata` : '— No .pdata section', color: result.exceptionEntries > 0 ? '#60a5fa' : '#374151' },
                      { label: 'Delayed Imports (B4)', value: result.delayedImports?.length > 0 ? result.delayedImports.join(', ') : '— None detected', color: result.delayedImports?.length > 0 ? '#c4b5fd' : '#374151' },
                      { label: 'Debug PDB Path (B8)', value: result.debugPdb || '— Not found (stripped binary)', color: result.debugPdb ? '#4ade80' : '#374151' },
                    ].map(({ label, value, color }) => (
                      <div key={label} style={{ display: 'flex', gap: 12, fontSize: 11, alignItems: 'flex-start' }}>
                        <span style={{ minWidth: 180, color: '#4b5563', fontWeight: 600, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em', paddingTop: 1 }}>{label}</span>
                        <span style={{ fontFamily: 'monospace', color, flex: 1, wordBreak: 'break-all' }}>{value}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            );
          })()}
          {tab === 'compare' && compareResult && !compareResult.error && (() => {
            const mkRow = (label, a, b, dangerFn) => {
              const diff = String(a) !== String(b);
              return (
                <div key={label} style={{ display: 'flex', gap: 0, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ width: 130, padding: '7px 12px', fontSize: 10, color: '#374151', fontWeight: 600, flexShrink: 0 }}>{label}</div>
                  <div style={{ flex: 1, padding: '7px 12px', fontSize: 11, fontFamily: 'monospace', color: diff ? '#fbbf24' : '#94a3b8', background: 'rgba(255,255,255,0.01)' }}>{String(a)}</div>
                  <div style={{ flex: 1, padding: '7px 12px', fontSize: 11, fontFamily: 'monospace', color: diff ? '#fbbf24' : '#94a3b8', background: 'rgba(255,255,255,0.01)', borderLeft: '1px solid rgba(255,255,255,0.04)' }}>{String(b)}</div>
                </div>
              );
            };
            return (
              <>
              <Card>
                <CardHeader>Binary Diff — {file?.name}  — {compareFile?.name}</CardHeader>
                <div style={{ padding: '6px 16px 4px', display: 'flex', fontSize: 10, color: '#374151', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ width: 130 }} />
                  <div style={{ flex: 1, fontWeight: 600, color: '#818cf8', padding: '0 12px' }}>{file?.name?.slice(0, 30)}</div>
                  <div style={{ flex: 1, fontWeight: 600, color: '#60a5fa', padding: '0 12px', borderLeft: '1px solid rgba(255,255,255,0.04)' }}>{compareFile?.name?.slice(0, 30)}</div>
                </div>
                {mkRow('Architecture', result.arch, compareResult.arch)}
                {mkRow('Risk Score',   result.riskScore, compareResult.riskScore)}
                {mkRow('Entropy',      result.overallEntropy?.toFixed(3), compareResult.overallEntropy?.toFixed(3))}
                {mkRow('Sections',     result.numSec, compareResult.numSec)}
                {mkRow('Imports (DLL)',result.imports?.length || 0, compareResult.imports?.length || 0)}
                {mkRow('Denuvo',       result.denuvo ? 'YES' : 'NO', compareResult.denuvo ? 'YES' : 'NO')}
                {mkRow('VMProtect',    result.vmp ? 'YES' : 'NO', compareResult.vmp ? 'YES' : 'NO')}
                {mkRow('Anti-Debug',   result.antiDebug ? 'YES' : 'NO', compareResult.antiDebug ? 'YES' : 'NO')}
                {mkRow('Anti-VM',      result.antiVM ? 'YES' : 'NO', compareResult.antiVM ? 'YES' : 'NO')}
                {mkRow('Packers',      result.packers?.join(', ') || '—', compareResult.packers?.join(', ') || '—')}
                {mkRow('Flagged Str.', result.strings?.filter(s=>s.cat).length || 0, compareResult.strings?.filter(s=>s.cat).length || 0)}

                {/* Section diff */}
                <div style={{ padding: '10px 16px 4px', fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Sections</div>
                <div style={{ maxHeight: 300, overflowY: 'auto' }}>
                  {result.sections.map((s, i) => {
                    const s2 = compareResult.sections[i];
                    const entropyDiff = s2 ? Math.abs(s.entropy - s2.entropy) > 0.15 : false;
                    return (
                      <div key={i} style={{ display: 'flex', gap: 0, borderBottom: '1px solid rgba(255,255,255,0.04)', alignItems: 'center' }}>
                        <div style={{ width: 130, padding: '6px 12px', fontSize: 10, color: '#4b5563', fontFamily: 'monospace', flexShrink: 0 }}>{s.name}</div>
                        <div style={{ flex: 1, padding: '6px 12px', fontSize: 10, fontFamily: 'monospace', color: '#94a3b8' }}>H={s.entropy.toFixed(3)}</div>
                        <div style={{ flex: 1, padding: '6px 12px', fontSize: 10, fontFamily: 'monospace', color: entropyDiff ? '#fbbf24' : '#94a3b8', borderLeft: '1px solid rgba(255,255,255,0.04)' }}>H={s2 ? s2.entropy.toFixed(3) : '—'} {entropyDiff && '?'}</div>
                      </div>
                    );
                  })}
                </div>
              </Card>

              {/* B6 — Byte-level Hex Diff (Enhanced — FAZ 4.2) */}
              {scanRawBytes && compareRawBytes && (() => {
                const LEN = Math.min(scanRawBytes.length, compareRawBytes.length, 2048);
                let diffCount = 0;
                const diffRegions = []; // contiguous diff ranges
                let inDiff = false, regionStart = 0;
                for (let i = 0; i < LEN; i++) {
                  const d = scanRawBytes[i] !== compareRawBytes[i];
                  if (d) diffCount++;
                  if (d && !inDiff) { inDiff = true; regionStart = i; }
                  if (!d && inDiff) { inDiff = false; diffRegions.push({ start: regionStart, end: i }); }
                }
                if (inDiff) diffRegions.push({ start: regionStart, end: LEN });

                // Import diff (LCS-based)
                const dlls1 = (result.imports || []).map(i => i.dll).sort();
                const dlls2 = (compareResult.imports || []).map(i => i.dll).sort();
                const addedDlls = dlls2.filter(d => !dlls1.includes(d));
                const removedDlls = dlls1.filter(d => !dlls2.includes(d));
                const commonDlls = dlls1.filter(d => dlls2.includes(d));

                // String diff
                const str1 = new Set((result.strings || []).map(s => s.text || s));
                const str2 = new Set((compareResult.strings || []).map(s => s.text || s));
                const addedStrs = [...str2].filter(s => !str1.has(s)).slice(0, 20);
                const removedStrs = [...str1].filter(s => !str2.has(s)).slice(0, 20);

                const COLS = 16;
                const rows = Math.ceil(LEN / COLS);
                return (
                  <Card style={{ marginTop: 12 }}>
                    <CardHeader>Binary Diff (FAZ 4.2 Enhanced) — {LEN} bytes · {diffCount} differences ({((diffCount/LEN)*100).toFixed(1)}% changed) · {diffRegions.length} regions</CardHeader>

                    {/* Diff summary strip */}
                    <div style={{ padding: '8px 16px', display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ color: '#f87171' }}>Changed: {diffCount} bytes</span>
                      <span style={{ color: '#94a3b8' }}>Unchanged: {LEN - diffCount} bytes</span>
                      <span style={{ color: '#fbbf24' }}>Regions: {diffRegions.length}</span>
                      {scanRawBytes.length !== compareRawBytes.length && <span style={{ color: '#60a5fa' }}>Size diff: {Math.abs(scanRawBytes.length - compareRawBytes.length)} bytes</span>}
                    </div>

                    {/* Diff heatmap mini strip */}
                    <div style={{ padding: '4px 16px 8px', display: 'flex', height: 10, gap: 0 }}>
                      {Array.from({ length: Math.min(200, LEN) }, (_, i) => {
                        const idx = Math.floor(i * LEN / Math.min(200, LEN));
                        const d = scanRawBytes[idx] !== compareRawBytes[idx];
                        return <div key={i} style={{ flex: 1, background: d ? '#f87171' : 'rgba(255,255,255,0.03)', minWidth: 1 }} />;
                      })}
                    </div>

                    {/* Import diff */}
                    {(addedDlls.length > 0 || removedDlls.length > 0) && (
                      <div style={{ padding: '8px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', marginBottom: 4 }}>Import Diff (DLLs)</div>
                        <div style={{ display: 'flex', gap: 16, fontSize: 10, fontFamily: 'monospace' }}>
                          {removedDlls.length > 0 && <div>{removedDlls.map(d => <div key={d} style={{ color: '#f87171' }}>- {d}</div>)}</div>}
                          {addedDlls.length > 0 && <div>{addedDlls.map(d => <div key={d} style={{ color: '#4ade80' }}>+ {d}</div>)}</div>}
                          <div style={{ color: '#374151' }}>Common: {commonDlls.length}</div>
                        </div>
                      </div>
                    )}

                    {/* String diff */}
                    {(addedStrs.length > 0 || removedStrs.length > 0) && (
                      <div style={{ padding: '8px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', marginBottom: 4 }}>String Diff (first 20)</div>
                        <div style={{ display: 'flex', gap: 16, fontSize: 10, fontFamily: 'monospace', maxHeight: 120, overflowY: 'auto' }}>
                          {removedStrs.length > 0 && <div>{removedStrs.map((s,i) => <div key={i} style={{ color: '#f87171', wordBreak: 'break-all' }}>- {s}</div>)}</div>}
                          {addedStrs.length > 0 && <div>{addedStrs.map((s,i) => <div key={i} style={{ color: '#4ade80', wordBreak: 'break-all' }}>+ {s}</div>)}</div>}
                        </div>
                      </div>
                    )}

                    {/* Hex grid */}
                    <div style={{ overflowX: 'auto', padding: '8px 0', maxHeight: 500, overflowY: 'auto' }}>
                      <div style={{ fontFamily: 'monospace', fontSize: 10, minWidth: 700 }}>
                        {Array.from({ length: rows }, (_, row) => {
                          const start = row * COLS;
                          return (
                            <div key={row} style={{ display: 'flex', gap: 0, alignItems: 'center', padding: '1px 16px', background: row % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                              <span style={{ color: '#1f2937', minWidth: 50 }}>{(start).toString(16).toUpperCase().padStart(6,'0')}</span>
                              <div style={{ display: 'flex', gap: 2, flex: 1 }}>
                                {Array.from({ length: COLS }, (_, col) => {
                                  const idx = start + col;
                                  if (idx >= LEN) return <span key={col} style={{ minWidth: 20 }} />;
                                  const a = scanRawBytes[idx], b = compareRawBytes[idx];
                                  const diff = a !== b;
                                  return (
                                    <span key={col} style={{ minWidth: 20, color: diff ? '#f87171' : '#374151', background: diff ? 'rgba(239,68,68,0.1)' : undefined, borderRadius: 2, textAlign: 'center' }}
                                      title={diff ? `File1: ${a.toString(16).padStart(2,'0')} / File2: ${b.toString(16).padStart(2,'0')}` : undefined}>
                                      {a.toString(16).padStart(2,'0')}
                                    </span>
                                  );
                                })}
                              </div>
                              <div style={{ display: 'flex', gap: 2, flex: 1, borderLeft: '1px solid rgba(255,255,255,0.04)', paddingLeft: 8 }}>
                                {Array.from({ length: COLS }, (_, col) => {
                                  const idx = start + col;
                                  if (idx >= LEN) return <span key={col} style={{ minWidth: 20 }} />;
                                  const a = scanRawBytes[idx], b = compareRawBytes[idx];
                                  const diff = a !== b;
                                  return (
                                    <span key={col} style={{ minWidth: 20, color: diff ? '#f87171' : '#374151', background: diff ? 'rgba(239,68,68,0.1)' : undefined, borderRadius: 2, textAlign: 'center' }}>
                                      {b.toString(16).padStart(2,'0')}
                                    </span>
                                  );
                                })}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </Card>
                );
              })()}
              </>
            );
          })()}

          {/* C2 — İki dosyayı AI'da karşılaştır */}
          {tab === 'compare' && compareResult && !compareResult.error && (
            <div style={{ marginTop: 8, display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => onSendToAI({
                  comparison: true,
                  fileA: { name: file?.name, sha256: result.sha256, arch: result.arch, riskScore: result.riskScore, sections: result.sections, imports: result.imports, denuvo: result.denuvo, vmp: result.vmp, antiDebug: result.antiDebug, packers: result.packers, overallEntropy: result.overallEntropy },
                  fileB: { name: compareFile?.name, sha256: compareResult.sha256, arch: compareResult.arch, riskScore: compareResult.riskScore, sections: compareResult.sections, imports: compareResult.imports, denuvo: compareResult.denuvo, vmp: compareResult.vmp, antiDebug: compareResult.antiDebug, packers: compareResult.packers, overallEntropy: compareResult.overallEntropy },
                }, `${file?.name}  — ${compareFile?.name}`)}
                style={{ fontSize: 11, padding: '6px 16px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.07)', color: '#a78bfa', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Bot size={13} /> İki Dosyayı AI'da Karşılaştır (C2)
              </button>
            </div>
          )}

          {/* 23 — second file drop zone (shown after first scan, before compare tab exists) */}
          {tab !== 'compare' && result && (
            <div style={{ marginTop: 4 }}>
              <div onClick={() => !compareFile && compareRef.current.click()}
                onDrop={e => { e.preventDefault(); setCompareDragOver(false); processCompareFile(e.dataTransfer.files[0]); }}
                onDragOver={e => { e.preventDefault(); setCompareDragOver(true); }}
                onDragLeave={() => setCompareDragOver(false)}
                style={{ borderRadius: 10, padding: '10px 14px', border: `1px dashed ${compareDragOver ? 'rgba(96,165,250,0.5)' : 'rgba(255,255,255,0.06)'}`, background: compareDragOver ? 'rgba(96,165,250,0.04)' : 'transparent', cursor: compareFile ? 'default' : 'pointer', display: 'flex', alignItems: 'center', gap: 10, transition: 'all 0.15s' }}>
                <FileSearch size={14} color="#374151" style={{ flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: '#374151' }}>
                  {comparingFile ? 'Taranıyor…' : compareFile ? ` ile Karşılaştırma` : 'Karşılaştırmak için ikinci dosya bırak → "Diff ↓" sekmesi açılır'}
                </span>
                {compareFile && !comparingFile && (
                  <button onClick={e => { e.stopPropagation(); setCompareFile(null); setCompareResult(null); }} style={{ marginLeft: 'auto', fontSize: 10, color: '#f87171', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
                )}
                <input ref={compareRef} type="file" accept=".exe,.dll,.sys,*" onChange={e => processCompareFile(e.target.files[0])} style={{ display: 'none' }} />
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}

function PatchCard({ patch, onToggle, onDelete }) {
  const [h, setH] = useState(false);
  return (
    <div onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{ borderRadius: 10, padding: '12px 15px', transition: 'all 0.13s', background: patch.applied ? 'rgba(34,197,94,0.04)' : patch.enabled ? 'rgba(245,158,11,0.03)' : 'rgba(255,255,255,0.015)', border: `1px solid ${patch.applied ? 'rgba(34,197,94,0.22)' : patch.enabled ? 'rgba(245,158,11,0.18)' : 'rgba(255,255,255,0.05)'}` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button onClick={onToggle} style={{ width: 18, height: 18, borderRadius: 4, border: `2px solid ${patch.enabled ? '#f59e0b' : '#2d3748'}`, background: patch.enabled ? '#f59e0b' : 'transparent', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {patch.enabled && <span style={{ color: '#000', fontSize: 9, fontWeight: 900 }}>✓</span>}
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: patch.applied ? '#4ade80' : '#e2e8f0' }}>{patch.name}</span>
            {patch.applied && <span style={{ fontSize: 9, color: '#4ade80', background: 'rgba(34,197,94,0.11)', padding: '1px 6px', borderRadius: 4, fontWeight: 700 }}>APPLIED</span>}
          </div>
          <div style={{ display: 'flex', gap: 14, marginTop: 5 }}>
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#4b5563' }}>@ {patch.offset}</span>
            {patch.original && <span style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#374151' }}>orig </span><span style={{ color: '#ef4444' }}>{patch.original}</span></span>}
            {patch.patched  && <span style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#374151' }}>? </span><span style={{ color: '#4ade80' }}>{patch.patched}</span></span>}
          </div>
        </div>
        {h && <button onClick={onDelete} style={{ width: 28, height: 28, borderRadius: 6, border: 'none', background: 'rgba(239,68,68,0.09)', color: '#f87171', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Trash2 size={13} /></button>}
      </div>
    </div>
  );
}

function PatcherPage({ onSendToChat }) {
  const [patchFile,    setPatchFile]    = useState(null);
  const [patchBytes,   setPatchBytes]   = useState(null);  // 45 — raw bytes for pattern search
  const [patches, setPatches] = useState([
    { id: 1, name: 'NOP License Check',   offset: '0x004A1B2C', original: 'FF D0 84 C0 74 0E', patched: '90 90 90 90 90 90', enabled: true,  applied: false },
    { id: 2, name: 'Skip Steam Init',     offset: '0x00521FF0', original: 'E8 3B 00 00 00',    patched: '90 90 90 90 90',    enabled: false, applied: false },
    { id: 3, name: 'Disable Intro Video', offset: '0x00389A10', original: 'E8 C4 2A 00 00 85', patched: '33 C0 40 90 90 90', enabled: true,  applied: false },
  ]);
  const [showForm,     setShowForm]     = useState(false);
  const [form,         setForm]         = useState({ name: '', offset: '', original: '', patched: '' });
  const [dragOver,     setDragOver]     = useState(false);
  const [applyStatus,  setApplyStatus]  = useState(null);
  const [hexData,      setHexData]      = useState(null);
  const [hexLoading,   setHexLoading]   = useState(false);
  const [patHex,       setPatHex]       = useState('');   // 45
  const [patResults,   setPatResults]   = useState(null); // 45
  const ref           = useRef(null);
  const jsonImportRef = useRef(null);                     // 46
  // D3/D5 — Patch validation + before/after state
  const [patchValidation, setPatchValidation] = useState(null); // D3
  const [preApplyHex, setPreApplyHex]         = useState({});   // D5 — {patchId: hexBefore}
  // D4 — Conditional patch script
  const [scriptText, setScriptText] = useState('# Örnek:\n# if byte@0x00400000 == 0xE8 then patch 0x00400000 = 90 90 90 90 90\n');
  const [scriptResults, setScriptResults] = useState(null);
  const [showScript, setShowScript] = useState(false);
  // D6 — Bulk patch
  const [bulkFiles, setBulkFiles]     = useState([]); // {name, path, status}
  const [bulkRunning, setBulkRunning] = useState(false);
  const bulkRef = useRef(null);

  const enabledCount = patches.filter(p => p.enabled).length;
  const appliedCount = patches.filter(p => p.applied).length;

  // Load file + store raw bytes for pattern search (45)
  const loadPatchFile = (f) => {
    if (!f) return;
    setPatchFile(f); setPatchBytes(null); setPatResults(null);
    const reader = new FileReader();
    reader.onload = e => setPatchBytes(new Uint8Array(e.target.result));
    reader.readAsArrayBuffer(f);
  };

  // 45 — Byte pattern search (0xFF = wildcard)
  const searchPattern = () => {
    if (!patchBytes || !patHex.trim()) return;
    const bytes = patHex.trim().split(/[\s,]+/).map(h => parseInt(h, 16)).filter(n => !isNaN(n));
    if (!bytes.length) return;
    const offsets = [];
    outer: for (let i = 0; i <= patchBytes.length - bytes.length; i++) {
      for (let j = 0; j < bytes.length; j++)
        if (bytes[j] !== 0xFF && patchBytes[i + j] !== bytes[j]) continue outer;
      offsets.push(`0x${i.toString(16).toUpperCase().padStart(8,'0')}`);
      if (offsets.length >= 200) { offsets.push('⬦(limit 200)'); break; }
    }
    setPatResults(offsets);
  };

  // 46 — Export patches to JSON
  const exportPatches = () => {
    const blob = new Blob([JSON.stringify({ version: 1, patches }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `patches_${(patchFile?.name || 'export').replace(/\.[^.]+$/, '')}_${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(a.href);
  };

  // 46 — Import patches from JSON
  const importPatches = (f) => {
    if (!f) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const data = JSON.parse(e.target.result);
        if (Array.isArray(data.patches))
          setPatches(data.patches.map((p, i) => ({ ...p, id: Date.now() + i, applied: false })));
      } catch { alert('Geçersiz patch JSON dosyası.'); }
    };
    reader.readAsText(f);
  };

  // 42+43 — Real apply via Rust
  const applyPatches = async () => {
    if (!patchFile?.path) { setApplyStatus({ ok: false, msg: 'Tauri dosya yolu alınamadı. Dosyayı önce sürükle-bırak ile yükleyin.' }); return; }
    setApplyStatus(null); setPatchValidation(null);

    // D5 — capture before-apply hex for enabled patches
    const beforeHex = {};
    for (const p of patches.filter(x => x.enabled)) {
      try {
        const offset = parseInt(p.offset, 16) || parseInt(p.offset, 10) || 0;
        const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset, length: p.patched.trim().split(/\s+/).length });
        beforeHex[p.id] = hex;
      } catch {}
    }
    setPreApplyHex(beforeHex);

    try {
      const msg = await invoke('apply_patches', {
        filePath: patchFile.path,
        patches: patches.map(p => ({ name: p.name, offset: p.offset, patched: p.patched, enabled: p.enabled })),
      });
      setPatches(ps => ps.map(p => p.enabled ? { ...p, applied: true } : p));
      setApplyStatus({ ok: true, msg });

      // D3 — Validate: re-read bytes after apply and compare with expected
      const validation = [];
      for (const p of patches.filter(x => x.enabled)) {
        try {
          const offset = parseInt(p.offset, 16) || parseInt(p.offset, 10) || 0;
          const expected = p.patched.trim().split(/\s+/).map(h => parseInt(h, 16));
          const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset, length: expected.length });
          const actual = hex.split(/\s+/).map(h => parseInt(h, 16));
          const match = expected.every((b, i) => b === actual[i]);
          validation.push({ name: p.name, offset: p.offset, expected: p.patched, actual: hex.trim(), ok: match });
        } catch (e) {
          validation.push({ name: p.name, offset: p.offset, ok: false, error: String(e) });
        }
      }
      setPatchValidation(validation);
    } catch (e) {
      setApplyStatus({ ok: false, msg: String(e) });
    }
  };

  // 44 — Hex viewer
  const loadHex = async (patch) => {
    if (!patchFile?.path) return;
    if (hexData?.patchId === patch.id) { setHexData(null); return; } // toggle
    setHexLoading(true);
    try {
      const offset = parseInt(patch.offset, 16) || parseInt(patch.offset, 10) || 0;
      const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset, length: 128 });
      setHexData({ patchId: patch.id, hex, offset: patch.offset });
    } catch (e) { setHexData({ patchId: patch.id, hex: `Hata: ${e}`, offset: patch.offset }); }
    finally { setHexLoading(false); }
  };

  // D4 — Conditional patch script interpreter
  const runScript = async () => {
    if (!patchFile?.path) { setScriptResults([{ ok: false, msg: 'Dosya yüklü değilil' }]); return; }
    const lines = scriptText.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    const results = [];
    for (const line of lines) {
      const m = line.trim().match(/^if\s+byte@(0x[\da-f]+|\d+)\s*==\s*(0x[\da-f]+|\d+)\s+then\s+patch\s+(0x[\da-f]+|\d+)\s*=\s*([\da-f\s]+)$/i);
      if (!m) { results.push({ line, ok: false, msg: 'Sözdizimi hatası' }); continue; }
      const [, readOff, expected, patchOff, patchBytes] = m;
      try {
        const readN = parseInt(readOff); const expN = parseInt(expected);
        const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset: readN, length: 1 });
        const actual = parseInt(hex.trim().split(/\s+/)[0], 16);
        if (actual !== expN) { results.push({ line, ok: false, msg: `byte@${readOff} = 0x${actual.toString(16)} ≠ 0x${expected} ? skip` }); continue; }
        await invoke('apply_patches', { filePath: patchFile.path, patches: [{ name: `Script@${patchOff}`, offset: patchOff, patched: patchBytes.trim(), enabled: true }] });
        results.push({ line, ok: true, msg: `? patch 0x${parseInt(patchOff).toString(16)} applied` });
      } catch (e) { results.push({ line, ok: false, msg: String(e) }); }
    }
    setScriptResults(results);
  };

  // D6 — Bulk patch: apply current enabled patches to multiple files
  const runBulkPatch = async () => {
    const enabled = patches.filter(p => p.enabled);
    if (!enabled.length || !bulkFiles.length) return;
    setBulkRunning(true);
    setBulkFiles(prev => prev.map(f => ({ ...f, status: 'pending' })));
    for (let i = 0; i < bulkFiles.length; i++) {
      setBulkFiles(prev => prev.map((x, j) => j === i ? { ...x, status: 'running' } : x));
      try {
        await invoke('apply_patches', {
          filePath: bulkFiles[i].path,
          patches: enabled.map(p => ({ name: p.name, offset: p.offset, patched: p.patched, enabled: true })),
        });
        setBulkFiles(prev => prev.map((x, j) => j === i ? { ...x, status: 'done' } : x));
      } catch (e) {
        setBulkFiles(prev => prev.map((x, j) => j === i ? { ...x, status: 'error', error: String(e) } : x));
      }
    }
    setBulkRunning(false);
  };

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 22 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(245,158,11,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Binary size={17} color="#f59e0b" /></div>
            <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, color: '#f1f5f9' }}>Hex Patcher</h1>
          </div>
          <p style={{ fontSize: 12, color: '#374151', margin: 0 }}>Offset-based byte patching · NOP injection · Enable/disable patches before committing</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button onClick={() => setShowForm(true)} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.25)', background: 'rgba(245,158,11,0.07)', color: '#f59e0b', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><Plus size={13} /> New Patch</button>
          {patchFile && enabledCount > 0 && (
            <button onClick={applyPatches}
              style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Play size={13} /> Apply ({enabledCount}) & Save
            </button>
          )}
          {/* 46 — Export / Import JSON */}
          <button onClick={exportPatches} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.25)', background: 'rgba(96,165,250,0.07)', color: '#60a5fa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><Download size={13} /> Export JSON</button>
          <button onClick={() => jsonImportRef.current.click()} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.15)', background: 'transparent', color: '#60a5fa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><FolderOpen size={13} /> Import JSON</button>
          <input ref={jsonImportRef} type="file" accept=".json" onChange={e => importPatches(e.target.files[0])} style={{ display: 'none' }} />
          {patches.length > 0 && <button onClick={() => onSendToChat({ type: 'patcher', fileName: patchFile?.name, data: patches })} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.07)', color: '#a78bfa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><MessageSquare size={13} /> Chat'e Gönder</button>}
        </div>
      </div>

      {/* Target file */}
      <div onClick={() => !patchFile && ref.current.click()} onDrop={(e) => { e.preventDefault(); setDragOver(false); loadPatchFile(e.dataTransfer.files[0]); }} onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
        style={{ borderRadius: 12, marginBottom: 20, padding: patchFile ? '12px 16px' : '22px 16px', border: `1px ${patchFile ? 'solid' : 'dashed'} ${patchFile ? 'rgba(245,158,11,0.28)' : dragOver ? 'rgba(245,158,11,0.5)' : 'rgba(245,158,11,0.14)'}`, background: patchFile ? 'rgba(245,158,11,0.04)' : 'rgba(245,158,11,0.01)', cursor: patchFile ? 'default' : 'pointer', display: 'flex', alignItems: 'center', gap: 12, transition: 'all 0.18s' }}>
        <div style={{ width: 36, height: 36, borderRadius: 9, background: 'rgba(245,158,11,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Binary size={17} color="#f59e0b" /></div>
        {patchFile
          ? <><div style={{ flex: 1 }}><div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{patchFile.name}</div><div style={{ fontSize: 11, color: '#4b5563', marginTop: 2 }}>{(patchFile.size / 1048576).toFixed(2)} MB · {appliedCount}/{patches.length} patches applied{patchBytes ? ' · bytes loaded' : ''}</div></div><button onClick={e => { e.stopPropagation(); setPatchFile(null); setPatchBytes(null); setPatResults(null); }} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.22)', background: 'rgba(239,68,68,0.07)', color: '#f87171', cursor: 'pointer' }}>Remove</button></>
          : <div><div style={{ fontSize: 13, fontWeight: 500, color: '#6b7280' }}>Select target binary</div><div style={{ fontSize: 11, color: '#2d3748', marginTop: 2 }}>Drop an .exe or .dll, or click to browse</div></div>
        }
        <input ref={ref} type="file" accept=".exe,.dll,.sys,*" onChange={e => loadPatchFile(e.target.files[0])} style={{ display: 'none' }} />
      </div>

      {/* New patch form */}
      {showForm && (
        <div style={{ borderRadius: 12, marginBottom: 16, padding: 16, background: 'rgba(245,158,11,0.04)', border: '1px solid rgba(245,158,11,0.22)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', marginBottom: 13, textTransform: 'uppercase', letterSpacing: '0.07em' }}>New Patch</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
            {[{ key: 'name', label: 'Patch Name', ph: 'e.g. Skip Intro', mono: false }, { key: 'offset', label: 'File Offset', ph: '0x00400000', mono: true }, { key: 'original', label: 'Original Bytes', ph: 'FF D0 84 C0', mono: true }, { key: 'patched', label: 'Patched Bytes', ph: '90 90 90 90', mono: true }].map(({ key, label, ph, mono }) => (
              <div key={key}>
                <div style={{ fontSize: 10, color: '#374151', marginBottom: 5, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
                <input value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} placeholder={ph} style={{ width: '100%', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 10px', fontSize: 12, color: '#e2e8f0', fontFamily: mono ? 'monospace' : 'inherit', outline: 'none', boxSizing: 'border-box' }} />
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => { if (!form.name || !form.offset) return; setPatches(p => [...p, { id: Date.now(), ...form, enabled: true, applied: false }]); setForm({ name: '', offset: '', original: '', patched: '' }); setShowForm(false); }} style={{ fontSize: 11, padding: '6px 15px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontWeight: 500 }}>Add</button>
            <button onClick={() => setShowForm(false)} style={{ fontSize: 11, padding: '6px 13px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.07)', background: 'transparent', color: '#4b5563', cursor: 'pointer' }}>Cancel</button>
          </div>
        </div>
      )}

      {/* 45 — Byte pattern search */}
      {patchBytes && (
        <div style={{ marginBottom: 16, borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 9 }}>Pattern Search (45) — 0xFF = wildcard</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={patHex} onChange={e => setPatHex(e.target.value)} onKeyDown={e => e.key === 'Enter' && searchPattern()}
              placeholder="FF D0 || 74  ← boşlukla ay&#305;r, 0xFF wildcard"
              style={{ flex: 1, background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 10px', fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace', outline: 'none' }} />
            <button onClick={searchPattern}
              style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
              Ara
            </button>
          </div>
          {patResults !== null && (
            <div style={{ marginTop: 9 }}>
              {patResults.length === 0
                ? <span style={{ fontSize: 11, color: '#374151' }}>Eşleşme bulunamadıı.</span>
                : <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                    {patResults.map((off, i) => (
                      <span key={i} onClick={() => off.startsWith('0x') && setForm(f => ({ ...f, offset: off }))}
                        style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4, background: 'rgba(245,158,11,0.1)', color: '#fbbf24', cursor: off.startsWith('0x') ? 'pointer' : 'default', border: '1px solid rgba(245,158,11,0.2)' }}
                        title={off.startsWith('0x') ? 'Offset\'i forma aktar' : ''}>
                        {off}
                      </span>
                    ))}
                  </div>
              }
              <div style={{ fontSize: 10, color: '#2d3748', marginTop: 5 }}>{patResults.filter(o => o.startsWith('0x')).length} offset bulundu — ofset'e tıklayarak New Patch formuna aktar</div>
            </div>
          )}
        </div>
      )}

      {/* D1 — NOP Sled generator + D2 — JMP/CALL injection */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
        {/* D1 — NOP sled */}
        <div style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(99,102,241,0.15)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 9 }}>NOP Sled Üreticisireticisi (D1)</div>
          {(() => {
            const [nopOff, setNopOff] = React.useState('0x00000000');
            const [nopLen, setNopLen] = React.useState('16');
            const genNop = () => {
              const len = Math.min(256, Math.max(1, parseInt(nopLen) || 16));
              const bytes = Array(len).fill('90').join(' ');
              const orig  = Array(len).fill('??').join(' ');
              setPatches(ps => [...ps, { id: Date.now(), name: `NOP Sled x${len}`, offset: nopOff, original: orig, patched: bytes, enabled: true, applied: false }]);
            };
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                <input value={nopOff} onChange={e => setNopOff(e.target.value)} placeholder="Offset (0x...)"
                  style={{ fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.05)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                <div style={{ display: 'flex', gap: 7, alignItems: 'center' }}>
                  <input value={nopLen} onChange={e => setNopLen(e.target.value)} placeholder="Uzunluk (byte)"
                    style={{ width: 100, fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.05)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                  <button onClick={genNop} style={{ flex: 1, fontSize: 11, padding: '5px 10px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>
                    Oluştur + Ekle
                  </button>
                </div>
              </div>
            );
          })()}
        </div>

        {/* D2 — JMP/CALL relative offset injection */}
        <div style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(245,158,11,0.15)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 9 }}>JMP / CALL Enjeksiyonu (D2)</div>
          {(() => {
            const [src, setSrc] = React.useState('0x00000000');
            const [tgt, setTgt] = React.useState('0x00000000');
            const [type, setType] = React.useState('JMP');
            const genJmp = () => {
              const srcN = parseInt(src, 16) || 0;
              const tgtN = parseInt(tgt, 16) || 0;
              const op   = type === 'JMP' ? 'E9' : 'E8';
              const rel  = ((tgtN - (srcN + 5)) >>> 0) & 0xFFFFFFFF;
              const b    = [(rel & 0xFF), ((rel >> 8) & 0xFF), ((rel >> 16) & 0xFF), ((rel >> 24) & 0xFF)];
              const bytes = `${op} ${b.map(x => x.toString(16).padStart(2,'0').toUpperCase()).join(' ')}`;
              setPatches(ps => [...ps, { id: Date.now(), name: `${type} @${src}?${tgt}`, offset: src, original: '?? ?? ?? ?? ??', patched: bytes, enabled: true, applied: false }]);
            };
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  {['JMP', 'CALL'].map(t => (
                    <button key={t} onClick={() => setType(t)}
                      style={{ flex: 1, fontSize: 11, padding: '4px 0', borderRadius: 5, border: `1px solid ${type===t ? 'rgba(245,158,11,0.5)' : 'rgba(255,255,255,0.08)'}`, background: type===t ? 'rgba(245,158,11,0.12)' : 'transparent', color: type===t ? '#f59e0b' : '#4b5563', cursor: 'pointer', fontWeight: 700 }}>{t}</button>
                  ))}
                </div>
                <input value={src} onChange={e => setSrc(e.target.value)} placeholder="Kaynak offset (0x...)"
                  style={{ fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.04)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                <div style={{ display: 'flex', gap: 7, alignItems: 'center' }}>
                  <input value={tgt} onChange={e => setTgt(e.target.value)} placeholder="Hedef offset (0x...)"
                    style={{ flex: 1, fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.04)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                  <button onClick={genJmp} style={{ fontSize: 11, padding: '5px 10px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: '#f59e0b', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
                    + Ekle
                  </button>
                </div>
              </div>
            );
          })()}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <span style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Patches ({patches.length})</span>
        <span style={{ fontSize: 10, color: '#2d3748' }}>{enabledCount} enabled · {appliedCount} applied</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {patches.map(p => (
          <div key={p.id}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ flex: 1 }}>
                <PatchCard patch={p} onToggle={() => setPatches(ps => ps.map(x => x.id === p.id ? { ...x, enabled: !x.enabled } : x))} onDelete={() => { setPatches(ps => ps.filter(x => x.id !== p.id)); if (hexData?.patchId === p.id) setHexData(null); }} />
              </div>
              {patchFile?.path && (
                <button onClick={() => loadHex(p)} disabled={hexLoading}
                  title="Hex görüntüle"
                  style={{ padding: '5px 9px', borderRadius: 6, border: `1px solid ${hexData?.patchId === p.id ? 'rgba(245,158,11,0.4)' : 'rgba(255,255,255,0.06)'}`, background: hexData?.patchId === p.id ? 'rgba(245,158,11,0.08)' : 'transparent', color: hexData?.patchId === p.id ? '#fbbf24' : '#374151', cursor: 'pointer', fontSize: 10, fontFamily: 'monospace', fontWeight: 600 }}>
                  HEX
                </button>
              )}
            </div>
            {/* 44 — Hex viewer panel + G2 minimap */}
            {hexData?.patchId === p.id && (
              <div style={{ margin: '4px 0 8px 0', borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(0,0,0,0.3)' }}>
                <div style={{ padding: '4px 12px', background: 'rgba(245,158,11,0.07)', fontSize: 10, color: '#f59e0b', fontWeight: 600, fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span>offset {hexData.offset} · 128 bytes</span>
                  {/* 2.3 — Hex range AI explanation */}
                  <button onClick={() => onSendToChat({ type: 'hex_region', fileName: patchFile?.name || '?', offset: hexData.offset, hex: hexData.hex })}
                    style={{ marginLeft: 'auto', padding: '2px 8px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.08)', color: '#a78bfa', cursor: 'pointer', fontSize: 9, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Bot size={10} /> AI'a Sor
                  </button>
                </div>
                <div style={{ display: 'flex', gap: 0 }}>
                  <pre style={{ margin: 0, padding: '10px 14px', fontSize: 11, color: '#94a3b8', fontFamily: 'monospace', lineHeight: 1.7, overflowX: 'auto', flex: 1 }}>{hexData.hex}</pre>
                  {/* G2 — Hex minimap: visual byte density bar */}
                  {(() => {
                    const bytes = hexData.hex.trim().split(/\s+/).map(h => parseInt(h, 16)).filter(n => !isNaN(n));
                    if (!bytes.length) return null;
                    const rows = Math.ceil(bytes.length / 16);
                    return (
                      <div style={{ width: 36, flexShrink: 0, background: 'rgba(0,0,0,0.2)', borderLeft: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', padding: '4px 3px', gap: 1, overflowY: 'auto' }} title="G2 — Hex Minimap">
                        {Array.from({ length: rows }, (_, r) => {
                          const row = bytes.slice(r * 16, (r + 1) * 16);
                          const nonNull = row.filter(b => b !== 0).length;
                          const allSame = row.every(b => b === row[0]);
                          const pct = nonNull / row.length;
                          const col = allSame && row[0] === 0x90 ? '#6366f1' : allSame ? '#fbbf24' : pct > 0.9 ? '#f87171' : pct > 0.5 ? '#60a5fa' : '#1f2937';
                          return <div key={r} style={{ height: 3, borderRadius: 1, background: col, opacity: 0.3 + pct * 0.7 }} />;
                        })}
                        <div style={{ fontSize: 7, color: '#1f2937', textAlign: 'center', marginTop: 2 }}>map</div>
                      </div>
                    );
                  })()}
                </div>
              </div>
            )}
          </div>
        ))}
        {patches.length === 0 && <div style={{ textAlign: 'center', padding: '40px 20px', color: '#2d3748', fontSize: 13 }}>No patches yet. Click "New Patch" to add one.</div>}
      </div>

      {/* Apply status (42+43) */}
      {applyStatus && (
        <div style={{ marginTop: 14, borderRadius: 9, padding: '10px 14px', background: applyStatus.ok ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)', border: `1px solid ${applyStatus.ok ? 'rgba(34,197,94,0.22)' : 'rgba(239,68,68,0.22)'}`, display: 'flex', alignItems: 'center', gap: 8 }}>
          {applyStatus.ok
            ? <CheckCircle2 size={14} color="#4ade80" />
            : <XCircle size={14} color="#f87171" />
          }
          <span style={{ fontSize: 11, color: applyStatus.ok ? '#4ade80' : '#f87171', fontFamily: 'monospace' }}>{applyStatus.msg}</span>
        </div>
      )}

      {/* D3 — Patch Validation Results */}
      {patchValidation && patchValidation.length > 0 && (
        <div style={{ marginTop: 12, borderRadius: 9, padding: '10px 14px', background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.15)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>Patch Validation (D3)</div>
          {patchValidation.map((v, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 5, fontSize: 11, fontFamily: 'monospace' }}>
              {v.ok ? <CheckCircle2 size={12} color="#4ade80" style={{ flexShrink: 0, marginTop: 1 }} /> : <XCircle size={12} color="#f87171" style={{ flexShrink: 0, marginTop: 1 }} />}
              <div>
                <span style={{ color: '#6366f1' }}>{v.name}</span>
                <span style={{ color: '#374151' }}> @{v.offset} — </span>
                {v.ok
                  ? <span style={{ color: '#4ade80' }}>OK ({v.actual})</span>
                  : <span style={{ color: '#f87171' }}>{v.error || `Expected: ${v.expected} / Got: ${v.actual}`}</span>
                }
                {/* D5 — Before/After */}
                {preApplyHex[patches.find(p => p.name === v.name)?.id] && (
                  <div style={{ marginTop: 3, color: '#1f2937' }}>
                    <span>Before: <span style={{ color: '#fbbf24' }}>{preApplyHex[patches.find(p => p.name === v.name)?.id]}</span></span>
                    <span style={{ marginLeft: 12 }}>After: <span style={{ color: '#4ade80' }}>{v.actual}</span></span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* D4 — Conditional Patch Script */}
      <div style={{ marginTop: 14 }}>
        <button onClick={() => setShowScript(s => !s)} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.25)', background: showScript ? 'rgba(139,92,246,0.1)' : 'transparent', color: '#a78bfa', cursor: 'pointer', fontWeight: 500 }}>
          ✎ Conditional Script (D4) {showScript ? '?' : '?'}
        </button>
        {showScript && (
          <div style={{ marginTop: 8, borderRadius: 9, padding: '12px 14px', background: 'rgba(139,92,246,0.04)', border: '1px solid rgba(139,92,246,0.18)' }}>
            <div style={{ fontSize: 9, color: '#4b5563', marginBottom: 6 }}>Sözdizimi: <code style={{ color: '#a78bfa' }}>if byte@OFFSET == VALUE then patch TARGET = BYTES</code></div>
            <textarea value={scriptText} onChange={e => setScriptText(e.target.value)} rows={5}
              style={{ width: '100%', fontFamily: 'monospace', fontSize: 11, padding: '8px 10px', borderRadius: 7, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(139,92,246,0.2)', color: '#c4b5fd', outline: 'none', resize: 'vertical', boxSizing: 'border-box' }} />
            <button onClick={runScript} style={{ marginTop: 6, fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.35)', background: 'rgba(139,92,246,0.1)', color: '#a78bfa', cursor: 'pointer', fontWeight: 600 }}>▶ Script'i Çalıştır</button>
            {scriptResults && (
              <div style={{ marginTop: 8 }}>
                {scriptResults.map((r, i) => (
                  <div key={i} style={{ fontSize: 10, fontFamily: 'monospace', padding: '3px 0', color: r.ok ? '#4ade80' : '#f87171' }}>
                    {r.ok ? '?' : '✗'} {r.msg} — <span style={{ color: '#374151' }}>{r.line}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* D6 — Bulk Patch */}
      {patches.filter(p => p.enabled).length > 0 && (
        <div style={{ marginTop: 14, borderRadius: 9, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Bulk Patch (D6) — Apply to multiple files</div>
            <button onClick={() => bulkRef.current.click()} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.07)', color: '#f59e0b', cursor: 'pointer' }}>+ Dosya Ekle</button>
            <input ref={bulkRef} type="file" multiple accept=".exe,.dll,.sys" onChange={e => {
              const files = Array.from(e.target.files).filter(f => f.path);
              setBulkFiles(prev => [...prev, ...files.map(f => ({ name: f.name, path: f.path, status: 'ready' }))]);
            }} style={{ display: 'none' }} />
            {bulkFiles.length > 0 && !bulkRunning && <button onClick={runBulkPatch} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', fontWeight: 600 }}>▶ Hepsine Uygula</button>}
            {bulkFiles.length > 0 && <button onClick={() => setBulkFiles([])} style={{ fontSize: 10, padding: '3px 8px', borderRadius: 6, border: 'none', background: 'transparent', color: '#374151', cursor: 'pointer', marginLeft: 'auto' }}>Temizle</button>}
          </div>
          {bulkFiles.length === 0 && <div style={{ fontSize: 11, color: '#374151' }}>Dosya yolu gerektiriyor — Tauri drag-drop ile yüklenen dosyalar.</div>}
          {bulkFiles.map((f, i) => {
            const col = f.status === 'done' ? '#4ade80' : f.status === 'error' ? '#f87171' : f.status === 'running' ? '#fbbf24' : '#374151';
            return (
              <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 11, padding: '3px 0' }}>
                <span style={{ color: col }}>{f.status === 'running' ? '⏳' : f.status === 'done' ? '?' : f.status === 'error' ? '✗' : '?'}</span>
                <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{f.name}</span>
                {f.error && <span style={{ color: '#f87171', fontSize: 10 }}>{f.error}</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// —�—�—� System Page (GPU + Model Manager) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

function SystemPage() {
  const [sysInfo, setSysInfo]     = useState(null);
  const [loadingSys, setLoadingSys] = useState(false);
  const [modelsDir, setModelsDir] = useState(() => localStorage.getItem('dissect_models_dir') || '');
  const [models, setModels]       = useState([]);
  const [dlUrl, setDlUrl]         = useState('');
  const [dlName, setDlName]       = useState('');
  const [dlProgress, setDlProgress] = useState(null);
  const [dlError, setDlError]     = useState('');
  const [cudaInfo, setCudaInfo]   = useState(null);
  const [checkingCuda, setCheckingCuda] = useState(false);
  // HuggingFace GGUF arama
  const [hfQuery, setHfQuery]     = useState('');
  const [hfResults, setHfResults] = useState([]);
  const [hfSearching, setHfSearching] = useState(false);
  const [hfError, setHfError]     = useState('');
  const [hfExpanded, setHfExpanded] = useState(null); // expanded model id

  const refreshSys = async () => {
    setLoadingSys(true);
    try { setSysInfo(await invoke('get_system_info')); }
    catch (e) { console.error(e); }
    finally { setLoadingSys(false); }
  };

  const scanModels = async () => {
    if (!modelsDir) return;
    localStorage.setItem('dissect_models_dir', modelsDir);
    try { setModels(await invoke('list_models', { dir: modelsDir })); }
    catch (e) { console.error(e); }
  };

  const searchHfGguf = async () => {
    if (!hfQuery.trim()) return;
    setHfSearching(true); setHfError(''); setHfResults([]);
    try {
      const results = await invoke('search_hf_gguf', { query: hfQuery.trim() });
      setHfResults(Array.isArray(results) ? results : []);
      if (!Array.isArray(results) || results.length === 0) setHfError('Sonuç bulunamadı. Farklı bir arama terimi deneyin.');
    } catch (e) { setHfError(String(e)); }
    finally { setHfSearching(false); }
  };

  const startDownload = async () => {
    if (!dlUrl || !dlName || !modelsDir) return;
    const dest = `${modelsDir}\\${dlName}`;
    setDlProgress({ pct: 0, mb: 0, total_mb: 0 });
    setDlError('');
    const unlisten = await listen('dl-progress', (e) => setDlProgress(e.payload));
    try {
      await invoke('download_model', { url: dlUrl, dest });
      await scanModels();
      setDlUrl(''); setDlName('');
    } catch (e) { setDlError(String(e)); }
    finally { setDlProgress(null); unlisten(); }
  };

  const checkCuda = async () => {
    setCheckingCuda(true);
    try { setCudaInfo(await invoke('get_cuda_version')); }
    catch { setCudaInfo(null); }
    finally { setCheckingCuda(false); }
  };

  useEffect(() => { refreshSys(); checkCuda(); }, []);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(20,184,166,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Cpu size={17} color="#2dd4bf" /></div>
          <div>
            <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, color: '#f1f5f9' }}>System</h1>
            <p style={{ fontSize: 12, color: '#374151', margin: 0 }}>Hardware info · GPU/CUDA · GGUF model manager</p>
          </div>
        </div>
        <button onClick={refreshSys} disabled={loadingSys} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer' }}>
          <RefreshCw size={13} style={loadingSys ? { animation: '_sp 0.75s linear infinite' } : {}} /> Refresh
        </button>
      </div>

      {loadingSys && !sysInfo && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spinner /></div>
      )}

      {sysInfo && (
        <>
          {/* Hardware row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
            {[
              { icon: <Cpu size={16} color="#818cf8" />, label: 'Processor', value: sysInfo.cpu, sub: `${sysInfo.cores} logical cores`, bg: 'rgba(99,102,241,0.09)', border: 'rgba(99,102,241,0.18)' },
              { icon: <MemoryStick size={16} color="#2dd4bf" />, label: 'Memory', value: `${sysInfo.ram_gb.toFixed(1)} GB`, sub: 'Total system RAM', bg: 'rgba(20,184,166,0.07)', border: 'rgba(20,184,166,0.15)' },
              { icon: <HardDrive size={16} color="#f59e0b" />, label: 'Operating System', value: sysInfo.os || 'Windows', sub: 'Platform', bg: 'rgba(245,158,11,0.07)', border: 'rgba(245,158,11,0.15)' },
            ].map(({ icon, label, value, sub, bg, border }) => (
              <div key={label} style={{ borderRadius: 12, padding: '14px 16px', background: bg, border: `1px solid ${border}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>{icon}<span style={{ fontSize: 10, fontWeight: 600, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</span></div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', marginBottom: 3, wordBreak: 'break-word' }}>{value}</div>
                <div style={{ fontSize: 10, color: '#2d3748' }}>{sub}</div>
              </div>
            ))}
          </div>

          {/* GPU Cards */}
          <div style={{ marginBottom: 8, fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>GPU / Compute</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12, marginBottom: 24 }}>
            {sysInfo.gpus.length === 0 && (
              <div style={{ borderRadius: 12, padding: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: '#374151', fontSize: 12 }}>
                No GPU detected via nvidia-smi or WMIC. If you have a discrete GPU, make sure drivers are installed.
              </div>
            )}
            {sysInfo.gpus.map((gpu, i) => (
              <div key={i} style={{ borderRadius: 12, padding: 16, background: gpu.cuda ? 'rgba(34,197,94,0.04)' : 'rgba(255,255,255,0.02)', border: `1px solid ${gpu.cuda ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.07)'}` }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', flex: 1, marginRight: 8 }}>{gpu.name}</div>
                  <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 5, background: gpu.cuda ? 'rgba(34,197,94,0.15)' : 'rgba(99,102,241,0.12)', color: gpu.cuda ? '#4ade80' : '#818cf8', whiteSpace: 'nowrap', flexShrink: 0 }}>
                    {gpu.cuda ? '? CUDA' : 'No CUDA'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {[
                    { label: 'VRAM',    value: gpu.vram_mb > 0 ? `${(gpu.vram_mb / 1024).toFixed(1)} GB` : '—' },
                    { label: 'Driver',  value: gpu.driver   || '—' },
                    { label: 'Compute', value: gpu.compute_cap || '—' },
                  ].map(({ label, value }) => (
                    <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 10, color: '#374151' }}>{label}</span>
                      <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6b7280' }}>{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Model Manager */}
      <div style={{ marginBottom: 8, fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>GGUF Model Manager</div>
      <Card style={{ marginBottom: 16 }}>
        <div style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#374151', marginBottom: 10 }}>
            Point to a folder containing <code style={{ fontFamily: 'monospace', color: '#818cf8' }}>.gguf</code> files. Ollama will use models you add via <code style={{ fontFamily: 'monospace', color: '#818cf8' }}>ollama create</code>.
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input value={modelsDir} onChange={e => setModelsDir(e.target.value)} placeholder="C:\Users\you\models" style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 11px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button onClick={scanModels} style={{ padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}><FolderOpen size={14} /> Scan</button>
          </div>

          {models.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>Found ({models.length})</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {models.map((m, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', padding: '9px 12px', borderRadius: 8, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.12)' }}>
                    <Layers size={14} color="#6366f1" style={{ marginRight: 10, flexShrink: 0 }} />
                    <span style={{ flex: 1, fontSize: 12, fontFamily: 'monospace', color: '#94a3b8' }}>{m.name}</span>
                    <span style={{ fontSize: 11, color: '#374151' }}>{m.size_mb.toFixed(0)} MB</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* HuggingFace GGUF Arama */}
          <div style={{ marginBottom: 16, borderRadius: 10, background: 'rgba(251,191,36,0.04)', border: '1px solid rgba(251,191,36,0.15)', padding: '12px 14px' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#fbbf24', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10 }}>🔍 HuggingFace GGUF Arama</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input value={hfQuery} onChange={e => setHfQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && searchHfGguf()}
                 placeholder="Örn: qwen2.5, llama-3, mistral-7b, phi-3&"
                style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(251,191,36,0.2)', borderRadius: 7, padding: '7px 11px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
              <button onClick={searchHfGguf} disabled={hfSearching || !hfQuery.trim()}
                style={{ padding: '7px 16px', borderRadius: 7, border: '1px solid rgba(251,191,36,0.3)', background: 'rgba(251,191,36,0.08)', color: '#fbbf24', cursor: hfSearching ? 'wait' : 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
                {hfSearching ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Aranıyor⬦</> : '🔍 Ara'}
              </button>
            </div>
            {hfError && <div style={{ fontSize: 11, color: '#f87171', marginBottom: 8 }}>{hfError}</div>}
            {hfResults.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 340, overflowY: 'auto' }}>
                {hfResults.map((m) => {
                  const mid = m.id || m.modelId || '';
                  const isExp = hfExpanded === mid;
                  const ggufFiles = (m.siblings || []).filter(s => s.rfilename?.endsWith('.gguf'));
                  return (
                    <div key={mid} style={{ borderRadius: 8, background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.12)', overflow: 'hidden' }}>
                      <div style={{ padding: '9px 12px', display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
                        onClick={() => setHfExpanded(isExp ? null : mid)}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mid}</div>
                          <div style={{ fontSize: 10, color: '#64748b', marginTop: 1, display: 'flex', gap: 10 }}>
                            <span>👍 {m.likes || 0}</span>
                            <span>? {(m.downloads || 0).toLocaleString()}</span>
                            {(m.tags || []).filter(t => t.startsWith('base_model')).slice(0,1).map(t => <span key={t} style={{ color: '#818cf8' }}>{t.replace('base_model:transform:','').replace('base_model:','')}</span>)}
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                          <a href={`https://huggingface.co/${mid}`} target="_blank" rel="noreferrer"
                            onClick={e => e.stopPropagation()}
                            style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', textDecoration: 'none' }}>
                            HF ↓
                          </a>
                          <span style={{ fontSize: 11, color: isExp ? '#818cf8' : '#4b5563' }}>{isExp ? '📂' : '📁'}</span>
                        </div>
                      </div>
                      {isExp && (
                        <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', padding: '8px 12px 10px' }}>
                          {ggufFiles.length === 0 ? (
                            <div style={{ fontSize: 11, color: '#4b5563' }}>Bu model i?in GGUF dosyası listelenmemiş. HuggingFace sayfasından manuel indirin.</div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                              <div style={{ fontSize: 10, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>GGUF Dosyaları ({ggufFiles.length})</div>
                              {ggufFiles.map(f => {
                                const dlLink = `https://huggingface.co/${mid}/resolve/main/${f.rfilename}`;
                                return (
                                  <div key={f.rfilename} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px', borderRadius: 6, background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.08)' }}>
                                    <span style={{ flex: 1, fontSize: 11, fontFamily: 'monospace', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.rfilename}</span>
                                    <button onClick={() => { setDlUrl(dlLink); setDlName(f.rfilename); }}
                                      style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0 }}>
                                      ↓ İndir
                                    </button>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Download from URL */}
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10 }}>URL'den İndir</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, marginBottom: 8 }}>
              <input value={dlUrl} onChange={e => setDlUrl(e.target.value)} placeholder="https://huggingface.co/⬦/resolve/main/model.gguf" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 11px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
              <input value={dlName} onChange={e => setDlName(e.target.value)} placeholder="filename.gguf" style={{ width: 160, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 11px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            </div>
            <button onClick={startDownload} disabled={!dlUrl || !dlName || !modelsDir || !!dlProgress}
              style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '7px 16px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: dlProgress ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 500 }}>
              <Download size={14} /> {dlProgress ? `Downloading ${dlProgress.pct}%⬦` : 'Download'}
            </button>
            {dlProgress && (
              <div style={{ marginTop: 10 }}>
                <div style={{ height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${dlProgress.pct}%`, background: 'linear-gradient(90deg,#6366f1,#22c55e)', borderRadius: 2, transition: 'width 0.4s' }} />
                </div>
                <div style={{ fontSize: 10, color: '#374151', marginTop: 5, fontFamily: 'monospace' }}>
                  {dlProgress.mb.toFixed(1)} MB / {dlProgress.total_mb.toFixed(1)} MB
                </div>
              </div>
            )}
            {dlError && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>{dlError}</div>}
          </div>
        </div>
      </Card>

      {/* —�—�—� CUDA Management —�—�—� */}
      <div style={{ marginBottom: 8, fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>CUDA Yönetimi</div>
      <Card style={{ marginBottom: 16 }}>
        <div style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 38, height: 38, borderRadius: 10, background: cudaInfo ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.09)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Cpu size={18} color={cudaInfo ? '#4ade80' : '#f87171'} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: cudaInfo ? '#4ade80' : '#f87171' }}>
                  {cudaInfo ? 'CUDA Kurulu' : 'CUDA Bulunamadı'}
                </div>
                <div style={{ fontSize: 11, color: '#4b5563', marginTop: 2, fontFamily: 'monospace' }}>
                  {cudaInfo || 'nvcc bulunamadı — Toolkit kurulmamış olabilir'}
                </div>
              </div>
            </div>
            <button onClick={checkCuda} disabled={checkingCuda}
              style={{ padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.07)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5 }}>
              <RefreshCw size={12} style={checkingCuda ? { animation: '_sp 0.75s linear infinite' } : {}} /> Kontrol Et
            </button>
          </div>

          {sysInfo?.gpus.some(g => g.cuda) && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>CUDA GPU'lar</div>
              {sysInfo.gpus.filter(g => g.cuda).map((gpu, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 12px', background: 'rgba(34,197,94,0.04)', borderRadius: 7, marginBottom: 5, border: '1px solid rgba(34,197,94,0.1)' }}>
                  <span style={{ fontSize: 12, color: '#6b7280' }}>{gpu.name}</span>
                  <div style={{ display: 'flex', gap: 14 }}>
                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#4ade80' }}>SM {gpu.compute_cap || '—'}</span>
                    <span style={{ fontSize: 11, color: '#374151' }}>{gpu.vram_mb > 0 ? `${(gpu.vram_mb / 1024).toFixed(1)} GB VRAM` : ''}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {!cudaInfo && (
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 12 }}>Kurulum Adımları</div>
              {[
                { n: '1', title: 'GPU Sürücüsü',        desc: 'En güncel NVIDIA sürücüsünü kurun (GeForce Experience veya nvidia.com)' },
                { n: '2', title: 'VS C++ Build Tools',   desc: 'CUDA derleyicisi için gerekli — Microsoft Build Tools 2022 kurun' },
                { n: '3', title: 'CUDA Toolkit',         desc: 'GPU Compute Capability\'nize uygun sürümü NVIDIA sitesinden indirin ve kurun' },
                { n: '4', title: 'Terminali Yeniden Başlat', desc: 'CUDA_PATH ve PATH değişkenleri otomatik eklenir — yeni terminal açın' },
                { n: '5', title: 'Doğrula',              desc: '"Kontrol Et" butonuna basın ya da terminalde: nvcc --version' },
              ].map(({ n, title, desc }) => (
                <div key={n} style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
                  <div style={{ width: 22, height: 22, borderRadius: 6, background: 'rgba(99,102,241,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: 10, fontWeight: 700, color: '#818cf8' }}>{n}</div>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#6b7280' }}>{title}</div>
                    <div style={{ fontSize: 11, color: '#374151', marginTop: 2 }}>{desc}</div>
                  </div>
                </div>
              ))}
              <a href="https://developer.nvidia.com/cuda-downloads" target="_blank" rel="noreferrer"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 6, padding: '7px 15px', borderRadius: 8, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', textDecoration: 'none', fontSize: 12, fontWeight: 500 }}>
                <Download size={13} /> CUDA Toolkit İndir
              </a>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

// —�—�—� Chat Page (LM Studio + GGUF Direct) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

function ChatPage({ chatContexts, setChatContexts, scanHistory }) {
  // —— Bağlantı modu: 'lms' = LM Studio, 'gguf' = Doğrudan GGUF ——
  const [chatMode, setChatMode]           = useState(() => localStorage.getItem('dissect_chat_mode') || 'lms');
  const [lmsUrl, setLmsUrl]               = useState(() => localStorage.getItem('dissect_lms_url') || 'http://localhost:1234');
  const [apiKey, setApiKey]               = useState(() => localStorage.getItem('dissect_lms_key') || '');
  const [models, setModels]               = useState([]);
  const [selectedModel, setSelectedModel] = useState(() => localStorage.getItem('dissect_lms_model') || '');
  const [connected, setConnected]         = useState(false);
  const [connecting, setConnecting]       = useState(false);
  const [connectError, setConnectError]   = useState('');
  // —— GGUF Direct state ——
  const [ggufPath, setGgufPath]           = useState(() => localStorage.getItem('dissect_gguf_path') || '');
  const [ggufPort, setGgufPort]           = useState(() => parseInt(localStorage.getItem('dissect_gguf_port') || '9999'));
  const [ggufServerUrl, setGgufServerUrl] = useState(null);
  const [ggufStarting, setGgufStarting]   = useState(false);
  const [ggufError, setGgufError]         = useState('');
  // —— Sohbet state ——
  const [messages, setMessages]           = useState([]);
  const [input, setInput]                 = useState('');
  const [streaming, setStreaming]         = useState(false);
  const [streamContent, setStreamContent] = useState('');
  const [mode, setMode]                   = useState('analyze');
  const contentRef = useRef('');
  const chatEndRef = useRef(null);
  // —— 2.1 Context Memory ——
  const [contextMemory, setContextMemory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_ctx_memory') || '[]'); } catch { return []; }
  });
  const [ctxMemoryEnabled, setCtxMemoryEnabled] = useState(() => localStorage.getItem('dissect_ctx_mem_on') !== 'false');
  const [ctxMemoryMax, setCtxMemoryMax]         = useState(() => parseInt(localStorage.getItem('dissect_ctx_mem_max') || '5'));
  const [ctxMemoryOpen, setCtxMemoryOpen]       = useState(false);

  // 2.4 — IOC extraction state
  const [extractedIOCs, setExtractedIOCs] = useState([]);
  const [iocPanelOpen, setIocPanelOpen]   = useState(false);

  // 2.4 — IOC extractor: parse AI messages for IPs, domains, hashes, file paths, URLs
  const extractIOCs = useCallback((text) => {
    if (!text) return [];
    const iocs = [];
    const seen = new Set();
    const add = (type, value) => { const k = type + ':' + value; if (!seen.has(k)) { seen.add(k); iocs.push({ type, value }); } };
    // IPv4
    const ipRe = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
    for (const m of text.matchAll(ipRe)) { if (!/^(?:0\.|127\.|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(m[0])) add('ip', m[0]); }
    // MD5
    for (const m of text.matchAll(/\b[a-fA-F0-9]{32}\b/g)) add('hash-md5', m[0]);
    // SHA1
    for (const m of text.matchAll(/\b[a-fA-F0-9]{40}\b/g)) add('hash-sha1', m[0]);
    // SHA256
    for (const m of text.matchAll(/\b[a-fA-F0-9]{64}\b/g)) add('hash-sha256', m[0]);
    // Domain
    for (const m of text.matchAll(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|io|ru|cn|xyz|top|tk|ml|ga|cf|cc|co|biz|me|pro|pw|ws|in|de|uk|fr|it|nl|br|au|kr|jp)\b/gi))
      add('domain', m[0].toLowerCase());
    // URL
    for (const m of text.matchAll(/https?:\/\/[^\s"'<>\]){},;]+/gi)) add('url', m[0]);
    // Windows paths
    for (const m of text.matchAll(/[A-Z]:\\(?:[^\s"'<>|*?\\]+\\)*[^\s"'<>|*?\\]+/g)) add('path', m[0]);
    // Unix paths
    for (const m of text.matchAll(/\/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|dev|proc|sys)\/[^\s"'<>|*?]+/g)) add('path', m[0]);
    // Registry keys
    for (const m of text.matchAll(/HK(?:LM|CU|CR|U|CC)\\[^\s"'<>|*?]+/g)) add('registry', m[0]);
    return iocs;
  }, []);

  // 2.4 — Auto-extract IOCs from new assistant messages
  useEffect(() => {
    const assistantMsgs = messages.filter(m => m.role === 'assistant');
    if (assistantMsgs.length === 0) return;
    const allText = assistantMsgs.map(m => m.content).join('\n');
    const iocs = extractIOCs(allText);
    setExtractedIOCs(iocs);
    if (iocs.length > 0) setIocPanelOpen(true);
  }, [messages, extractIOCs]);

  // 2.1 — Persist context memory
  useEffect(() => { localStorage.setItem('dissect_ctx_memory', JSON.stringify(contextMemory)); }, [contextMemory]);
  useEffect(() => { localStorage.setItem('dissect_ctx_mem_on', ctxMemoryEnabled); }, [ctxMemoryEnabled]);
  useEffect(() => { localStorage.setItem('dissect_ctx_mem_max', ctxMemoryMax); }, [ctxMemoryMax]);

  // 2.1 — Auto-add scan summaries to context memory
  useEffect(() => {
    if (!scanHistory || scanHistory.length === 0) return;
    const latest = scanHistory[0];
    if (!latest?.sha256) return;
    setContextMemory(prev => {
      if (prev.some(m => m.sha256 === latest.sha256)) return prev;
      const entry = {
        sha256: latest.sha256,
        fileName: latest.fileName || '?',
        riskScore: latest.riskScore,
        arch: latest.arch,
        denuvo: latest.denuvo,
        vmp: latest.vmp,
        antiDebug: latest.antiDebug,
        packers: latest.packers,
        ts: Date.now(),
      };
      return [entry, ...prev].slice(0, 20);
    });
  }, [scanHistory]);

  // 2.1 — Build context memory prompt
  const buildContextPrompt = useCallback(() => {
    if (!ctxMemoryEnabled || contextMemory.length === 0) return '';
    const items = contextMemory.slice(0, ctxMemoryMax);
    const lines = items.map((m, i) => {
      const parts = [`#${i + 1} ${m.fileName} (SHA256: ${m.sha256?.slice(0, 16)}...)`];
      parts.push(`  Arch: ${m.arch || '?'}, Risk: ${m.riskScore ?? '?'}/100`);
      if (m.denuvo) parts.push('  Denuvo: YES');
      if (m.vmp)    parts.push('  VMProtect: YES');
      if (m.antiDebug) parts.push('  Anti-Debug: YES');
      if (m.packers?.length) parts.push(`  Packers: ${m.packers.join(', ')}`);
      return parts.join('\n');
    });
    return `\n\n--- CONTEXT MEMORY (${items.length} recent scans) ---\nThe user has previously analyzed these binaries:\n${lines.join('\n\n')}\n--- END CONTEXT MEMORY ---`;
  }, [ctxMemoryEnabled, contextMemory, ctxMemoryMax]);






  // Aktif endpoint: LMS veya GGUF sunucusu
  const activeUrl   = chatMode === 'gguf' ? (ggufServerUrl || `http://127.0.0.1:${ggufPort}`) : lmsUrl;
  const activeModel = chatMode === 'gguf' ? 'local-model' : selectedModel;
  const isReady     = chatMode === 'gguf' ? !!ggufServerUrl : (connected && !!selectedModel);

  const startGgufServer = async () => {
    if (!ggufPath) { setGgufError('GGUF dosya yolu boş'); return; }
    setGgufStarting(true); setGgufError('');
    try {
      const url = await invoke('start_gguf_server', { ggufPath, port: ggufPort });
      // Sunucunun hazır olmasını bekle (poll)
      for (let i = 0; i < 15; i++) {
        await new Promise(r => setTimeout(r, 1000));
        try {
          const r = await fetch(`${url}/v1/models`);
          if (r.ok) { setGgufServerUrl(url); setGgufStarting(false); return; }
        } catch {}
      }
      // Timeout — gene de URL'i set et, kullanıcı denesin
      setGgufServerUrl(url);
      setGgufError('Sunucu yanıt vermedi — yine de deneyebilirsiniz.');
    } catch (e) { setGgufError(String(e)); }
    finally { setGgufStarting(false); }
  };

  // Helper: format a single context item to text
  const formatContextItem = useCallback((ctx) => {
    if (ctx.type === 'pe_analyst') {
      const { type, _id, _selected, _ts, ...rest } = ctx;
      return `[PE/Binary Analizi]\nDosya: ${ctx.fileName || '?'}\n${JSON.stringify(rest, null, 2)}`;
    }
    if (ctx.type === 'scanner') {
      const d = ctx.data;
      return `[Scanner Sonucu]\nDosya: ${ctx.fileName || '?'}\nMimari: ${d.arch}  EP: 0x${d.ep?.toString(16).toUpperCase()}  Risk: ${d.riskScore}/100\nDenuvo: ${d.denuvo ? 'EVET' : 'Hayır'}  VMProtect: ${d.vmp ? 'EVET' : 'Hayır'}  Themida: ${d.themida ? 'EVET' : 'Hayır'}\nEntropi: ${d.overallEntropy?.toFixed(3)} H  Şüpheli section: ${d.suspiciousCount}\nSectionlar:\n${d.sections?.map(s => `  ${s.name.padEnd(12)} entropi=${s.entropy.toFixed(3)} boyut=${(s.rsize/1024).toFixed(0)}KB${s.suspicious ? ' ⚠' : ''}`).join('\n') || ''}`;
    }
    if (ctx.type === 'patcher') {
      const patches = ctx.data;
      return `[Hex Patch Listesi]\nHedef: ${ctx.fileName || '?'}\n${patches.map(p => `- ${p.name}  @${p.offset}  ${p.original || '—'} → ${p.patched || '—'}  ${p.applied ? 'Uygulandı' : p.enabled ? 'Aktif' : 'Devre dışı'}`).join('\n')}`;
    }
    if (ctx.type === 'ai_analyst') {
      return `[AI Analyst Raporu]\n${ctx.data?.output || ''}`;
    }
    if (ctx.type === 'hex_region') {
      return `[Hex Bölge]\nDosya: ${ctx.fileName || '?'}  Offset: ${ctx.offset}  Boyut: ${ctx.hex?.trim().split(/\s+/).length || '?'} byte\n${ctx.hex}`;
    }
    if (ctx.type === 'disasm_func') {
      return `[Disassembly — ${ctx.funcName || '?'}]\nDosya: ${ctx.fileName || '?'}  Adres: ${ctx.funcAddr}  Mimari: ${ctx.arch || 'x86-64'}\n${ctx.assembly}`;
    }
    return JSON.stringify(ctx, null, 2);
  }, []);

  // Context label helper
  const contextLabel = useCallback((ctx) => {
    const icons = { pe_analyst: '🔬', scanner: '🛡', patcher: '🔧', ai_analyst: '🤖', hex_region: '📦', disasm_func: '💻' };
    const names = { pe_analyst: 'PE Analiz', scanner: 'Scanner', patcher: 'Patcher', ai_analyst: 'AI Rapor', hex_region: 'Hex Bölge', disasm_func: 'Decompile' };
    const icon = icons[ctx.type] || '📄';
    const name = names[ctx.type] || ctx.type;
    const file = ctx.fileName || ctx.funcName || '';
    return `${icon} ${name}${file ? ': ' + file : ''}`;
  }, []);

  // Toggle a context selection
  const toggleContext = useCallback((id) => {
    setChatContexts(prev => prev.map(c => c._id === id ? { ...c, _selected: !c._selected } : c));
  }, [setChatContexts]);

  // Remove a context
  const removeContext = useCallback((id) => {
    setChatContexts(prev => prev.filter(c => c._id !== id));
  }, [setChatContexts]);

  // Build merged prompt from selected contexts
  const buildSelectedContextPrompt = useCallback(() => {
    const selected = chatContexts.filter(c => c._selected);
    if (selected.length === 0) return '';
    const parts = selected.map((ctx, i) => `─── Kaynak ${i + 1}: ${contextLabel(ctx)} ───\n${formatContextItem(ctx)}`);
    return parts.join('\n\n');
  }, [chatContexts, formatContextItem, contextLabel]);

  // Track last processed contexts length to auto-detect new items
  const lastCtxLenRef = useRef(0);

  useEffect(() => {
    if (chatContexts.length <= lastCtxLenRef.current) {
      lastCtxLenRef.current = chatContexts.length;
      return;
    }
    lastCtxLenRef.current = chatContexts.length;
    // New context(s) added — build prompt from all selected
    const selected = chatContexts.filter(c => c._selected);
    if (selected.length === 0) return;
    const isDecompile = selected.some(c => c.type === 'disasm_func');
    if (isDecompile) setMode('explain');

    if (selected.length === 1) {
      const ctx = selected[0];
      // Single context — use descriptive prompt
      let text = formatContextItem(ctx);
      if (ctx.type === 'hex_region') text += '\n\nBu baytlar ne olabilir? Struct olarak tahmin et.';
      else if (ctx.type === 'disasm_func') text += '\n\nBu assembly kodunu C/C++ pseudocode\'a çevir.';
      else text += '\n\nBu veriler hakkında detaylı analiz yap.';
      setInput(text);
    } else {
      // Multiple contexts — merged view
      const merged = buildSelectedContextPrompt();
      setInput(merged + '\n\nYukarıdaki tüm verileri birlikte analiz et. Her kaynağı açıkla ve aralarındaki ilişkileri belirle.');
    }
  }, [chatContexts]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, streamContent]);

  // Context summarize: long conversation
  const summarizeConversation = async () => {
    if (!connected || !selectedModel || streaming) return;
    const digest = messages.map(m => `${m.role === 'user' ? 'Kullanıcı' : 'AI'}: ${m.content}`).join('\n');
    const prompt = `Aşağıdaki sohbetin kısa bir özetini çıkar (3-5 madde). Teknik bulguları ve önemli kararları listele:\n\n${digest}`;
    setStreaming(true);
    contentRef.current = '';
    setStreamContent('');
    const unChunk = await listen('chat-chunk', (e) => { contentRef.current += e.payload; setStreamContent(contentRef.current); });
    const unDone  = await listen('chat-done', () => {
      setMessages([{ role: 'assistant', content: `**Sohbet Özeti (${new Date().toLocaleTimeString('tr-TR')})**\n\n${contentRef.current}` }]);
      setStreamContent(''); setStreaming(false); unChunk(); unDone();
    });
    try {
      await invoke('lms_chat_stream', {
        messages: [
          { role: 'system', content: 'You are a helpful assistant that summarizes technical AI reverse engineering conversations in Turkish, concisely.' },
          { role: 'user', content: prompt },
        ],
        model: selectedModel, baseUrl: lmsUrl, apiKey,
      });
    } catch (e) {
      setMessages([{ role: 'assistant', content: `Özet hatası: ${e}` }]);
      setStreamContent(''); setStreaming(false); unChunk(); unDone();
    }
  };

  // 2.7 — YARA Rule Wizard state and logic
  const [yaraWizardOpen, setYaraWizardOpen] = useState(false);
  const [yaraRule, setYaraRule]       = useState('');
  const [yaraGenerating, setYaraGenerating] = useState(false);
  const [yaraRuleName, setYaraRuleName] = useState('custom_rule');

  const generateYaraFromContext = async () => {
    if (!connected || !selectedModel) return;
    setYaraGenerating(true); setYaraRule('');
    const selectedCtx = chatContexts.filter(c => c._selected);
    const ctxText = selectedCtx.length > 0
      ? selectedCtx.map((c, i) => `[Source ${i + 1}]\n${formatContextItem(c)}`).join('\n\n')
      : (scanHistory?.[0] ? JSON.stringify(scanHistory[0], null, 2).slice(0, 4000) : '');
    if (!ctxText) { setYaraGenerating(false); return; }
    let content = '';
    const unChunk = await listen('chat-chunk', (e) => { content += e.payload; setYaraRule(content); });
    const unDone  = await listen('chat-done', () => { setYaraGenerating(false); unChunk(); unDone(); });
    try {
      await invoke('lms_chat_stream', {
        messages: [
          { role: 'system', content: `You are an expert YARA rule writer. Generate a valid, well-structured YARA rule based on the provided binary analysis data. The rule name should be "${yaraRuleName}". Include:
- Proper meta section (author, date, description)
- Relevant strings (hex patterns, text strings, imports)
- A sound condition section
Output ONLY the YARA rule, no explanation.` },
          { role: 'user', content: `Generate a YARA rule from this binary analysis data:\n\n${ctxText}` },
        ],
        model: selectedModel, baseUrl: lmsUrl, apiKey,
      });
    } catch (e) {
      setYaraRule(`// Hata: ${e}`); setYaraGenerating(false); unChunk(); unDone();
    }
  };

  // 2.7 — YARA library (saved rules)
  const [yaraLibrary, setYaraLibrary] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_yara_lib') || '[]'); } catch { return []; }
  });
  useEffect(() => { localStorage.setItem('dissect_yara_lib', JSON.stringify(yaraLibrary)); }, [yaraLibrary]);

  const saveYaraRule = () => {
    if (!yaraRule.trim()) return;
    setYaraLibrary(prev => [{ name: yaraRuleName, rule: yaraRule, ts: Date.now() }, ...prev].slice(0, 50));
  };
  const deleteYaraRule = (idx) => setYaraLibrary(prev => prev.filter((_, i) => i !== idx));

  const connect = async () => {
    setConnecting(true); setConnectError(''); setConnected(false);
    try {
      const list = await invoke('lms_list_models', { baseUrl: lmsUrl, apiKey });
      setModels(list);
      setSelectedModel(list[0] || '');
      setConnected(true);
    } catch (e) { setConnectError(String(e)); }
    finally { setConnecting(false); }
  };

  const sendMessage = async () => {
    if (!input.trim() || streaming) return;
    if (!isReady) { setConnectError(chatMode === 'gguf' ? 'Önce GGUF sunucusunu başlatın.' : 'Önce LM Studio\'ya bağlanın ve model seçin.'); return; }
    const userMsg = { role: 'user', content: input.trim() };
    const history = [...messages, userMsg];
    setMessages(history);
    setInput('');
    setStreaming(true);
    contentRef.current = '';
    setStreamContent('');

    const unChunk = await listen('chat-chunk', (e) => {
      contentRef.current += e.payload;
      setStreamContent(contentRef.current);
    });
    const unDone = await listen('chat-done', () => {
      setMessages(prev => [...prev, { role: 'assistant', content: contentRef.current }]);
      setStreamContent('');
      setStreaming(false);
      unChunk(); unDone();
    });

    const curMode = AI_MODES.find(m => m.id === mode);
    const ctxPrompt = buildContextPrompt();
    // Inject selected context sources into system prompt
    const selectedCtx = chatContexts.filter(c => c._selected);
    let dataCtx = '';
    if (selectedCtx.length > 0) {
      dataCtx = '\n\n--- ACTIVE DATA SOURCES ---\n' +
        selectedCtx.map((ctx, i) => `[Source ${i + 1}: ${contextLabel(ctx)}]\n${formatContextItem(ctx)}`).join('\n\n') +
        '\n--- END DATA SOURCES ---\nUse the above data to provide informed, contextual answers.';
    }
    const systemContent = (curMode?.system || AI_MODES[1].system) + ctxPrompt + dataCtx +
      '\n\nIMPORTANT: At the very end of every response, on a new line, output a confidence line in format: [CONFIDENCE:XX%] where XX is 0-100 representing how confident you are in your analysis. Do not explain this line.';
    try {
      await invoke('lms_chat_stream', {
        messages: [
          { role: 'system', content: systemContent },
          ...history.map(m => ({ role: m.role, content: m.content })),
        ],
        model: activeModel,
        baseUrl: activeUrl,
        apiKey: chatMode === 'gguf' ? '' : apiKey,
      });
    } catch (e) {
      setMessages(prev => [...prev, { role: 'assistant', content: `Hata: ${e}` }]);
      setStreamContent('');
      setStreaming(false);
      unChunk(); unDone();
    }
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <style>{`@keyframes cursor-blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>

      {/* —� Connection bar —� */}
      <div style={{ padding: '14px 20px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.13)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <MessageSquare size={17} color="#818cf8" />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>AI Chat</span>
            </div>
            <p style={{ fontSize: 11, color: '#4b5563', margin: 0 }}>
              LM Studio entegrasyonu — analiz yap, konuş, keşfet.
            </p>
          </div>
        </div>

        {/* -- AI Chat Mode selector -- */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 10, flexWrap: 'wrap' }}>
          {AI_MODES.map(m => (
            <button key={m.id} onClick={() => setMode(m.id)}
              style={{ padding: '4px 12px', borderRadius: 7, border: `1px solid ${mode === m.id ? m.border : 'rgba(255,255,255,0.07)'}`, background: mode === m.id ? m.bg : 'transparent', color: mode === m.id ? m.color : '#374151', cursor: 'pointer', fontSize: 11, fontWeight: mode === m.id ? 600 : 400, transition: 'all 0.13s' }}>
              {m.label}
            </button>
          ))}
          <span style={{ fontSize: 10, color: '#4b5563', marginLeft: 2 }}>{AI_MODES.find(m => m.id === mode)?.desc}</span>
          {/* 2.7 — YARA Wizard toggle */}
          <button onClick={() => setYaraWizardOpen(v => !v)}
            style={{ marginLeft: 'auto', padding: '4px 11px', borderRadius: 7, border: `1px solid ${yaraWizardOpen ? 'rgba(245,158,11,0.4)' : 'rgba(255,255,255,0.07)'}`, background: yaraWizardOpen ? 'rgba(245,158,11,0.08)' : 'transparent', color: yaraWizardOpen ? '#fbbf24' : '#374151', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5, fontWeight: yaraWizardOpen ? 600 : 400 }}>
            <ShieldAlert size={12} /> YARA Sihirbazı
          </button>
        </div>

        {/* 2.7 — YARA Wizard Panel */}
        {yaraWizardOpen && (
          <div style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(245,158,11,0.03)', border: '1px solid rgba(245,158,11,0.15)', display: 'flex', flexDirection: 'column', gap: 10, flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <ShieldAlert size={14} color="#fbbf24" />
                <span style={{ fontSize: 12, fontWeight: 700, color: '#fbbf24' }}>YARA Kural Sihirbazı</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 10, color: '#4b5563' }}>Kural adı:</span>
                <input value={yaraRuleName} onChange={e => setYaraRuleName(e.target.value.replace(/[^a-zA-Z0-9_]/g, '_'))}
                  style={{ padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(0,0,0,0.2)', color: '#e5e7eb', fontSize: 10, width: 130, fontFamily: 'monospace' }} />
                <button onClick={generateYaraFromContext} disabled={yaraGenerating || !connected}
                  style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: !connected ? '#374151' : '#fbbf24', cursor: connected ? 'pointer' : 'not-allowed', fontSize: 10, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  {yaraGenerating ? <><RefreshCw size={10} className="spin" /> Üretiliyor...</> : <><Zap size={10} /> AI ile Üret</>}
                </button>
                {yaraRule && (
                  <>
                    <button onClick={saveYaraRule}
                      style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Download size={9} /> Kaydet
                    </button>
                    <button onClick={() => navigator.clipboard.writeText(yaraRule)}
                      style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Copy size={9} /> Kopyala
                    </button>
                  </>
                )}
              </div>
            </div>
            <textarea value={yaraRule} onChange={e => setYaraRule(e.target.value)} placeholder="Seçili bağlam kaynaklarından YARA kuralı üretmek için 'AI ile Üret' butonuna tıklayın veya burada elle yazın..."
              style={{ resize: 'vertical', minHeight: 120, maxHeight: 300, padding: '10px 12px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.12)', background: 'rgba(0,0,0,0.25)', color: '#e5e7eb', fontSize: 11, fontFamily: 'monospace', lineHeight: 1.5 }} />
            {/* YARA Library */}
            {yaraLibrary.length > 0 && (
              <div style={{ borderTop: '1px solid rgba(245,158,11,0.1)', paddingTop: 8 }}>
                <span style={{ fontSize: 10, fontWeight: 600, color: '#92400e' }}>Kural Kütüphanesi ({yaraLibrary.length})</span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6, maxHeight: 150, overflow: 'auto' }}>
                  {yaraLibrary.map((r, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 8px', borderRadius: 6, background: 'rgba(0,0,0,0.15)', border: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ fontSize: 10, color: '#d4d4d8', fontFamily: 'monospace' }}>{r.name}</span>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <span style={{ fontSize: 9, color: '#4b5563' }}>{new Date(r.ts).toLocaleDateString('tr-TR')}</span>
                        <button onClick={() => setYaraRule(r.rule)}
                          style={{ padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer', fontSize: 9 }}>Yükle</button>
                        <button onClick={() => deleteYaraRule(idx)}
                          style={{ padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer', fontSize: 9 }}>Sil</button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>

          {/* —�—� Mod seçici: LM Studio | GGUF Direct —�—� */}
          <div style={{ display: 'flex', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', overflow: 'hidden', marginRight: 4 }}>
            {[{id:'lms', label:'LM Studio', color:'#818cf8'}, {id:'gguf', label:'📦 GGUF Direct', color:'#fbbf24'}].map(opt => (
              <button key={opt.id} onClick={() => { setChatMode(opt.id); localStorage.setItem('dissect_chat_mode', opt.id); }}
                style={{ padding: '5px 14px', border: 'none', background: chatMode === opt.id ? (opt.id==='gguf' ? 'rgba(245,158,11,0.12)' : 'rgba(99,102,241,0.12)') : 'transparent', color: chatMode === opt.id ? opt.color : '#4b5563', cursor: 'pointer', fontSize: 11, fontWeight: chatMode === opt.id ? 700 : 400, transition: 'all 0.13s' }}>
                {opt.label}
              </button>
            ))}
          </div>

          {chatMode === 'lms' && (<>
            <input value={lmsUrl} onChange={e => { setLmsUrl(e.target.value); localStorage.setItem('dissect_lms_url', e.target.value); }}
              style={{ width: 200, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <input value={apiKey} onChange={e => { setApiKey(e.target.value); localStorage.setItem('dissect_lms_key', e.target.value); }} placeholder="API Key (opsiyonel)"
              type="password"
              style={{ width: 168, background: 'rgba(0,0,0,0.3)', border: `1px solid ${apiKey ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.08)'}`, borderRadius: 7, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button onClick={connect} disabled={connecting}
              style={{ padding: '6px 15px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: connecting ? 'wait' : 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
              {connecting ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Bağlanıyor…</> : connected ? <><RefreshCw size={13} /> Yenile</> : 'Bağlan'}
            </button>
            {connected && models.length > 0 && (
              <select value={selectedModel} onChange={e => { setSelectedModel(e.target.value); localStorage.setItem('dissect_lms_model', e.target.value); }}
                style={{ flex: 1, minWidth: 200, maxWidth: 380, background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 7, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none' }}>
                {models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto' }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: connected ? '#22c55e' : '#ef4444', boxShadow: connected ? '0 0 6px #22c55e88' : 'none' }} />
              <span style={{ fontSize: 11, color: connected ? '#4ade80' : '#94a3b8' }}>{connected ? `${models.length} model` : 'Bağlı değil'}</span>
            </div>
          </>)}

          {chatMode === 'gguf' && (<>
            <input value={ggufPath} onChange={e => { setGgufPath(e.target.value); localStorage.setItem('dissect_gguf_path', e.target.value); }}
              placeholder="C:\models\qwen2.5-7b-q4.gguf"
              style={{ flex: 1, minWidth: 260, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 7, padding: '6px 10px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <input value={ggufPort} onChange={e => { const v = parseInt(e.target.value)||9999; setGgufPort(v); localStorage.setItem('dissect_gguf_port', v); }}
              type="number" min="1024" max="65535"
              style={{ width: 78, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 7, padding: '6px 8px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button onClick={startGgufServer} disabled={ggufStarting || !ggufPath}
              style={{ padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.35)', background: ggufServerUrl ? 'rgba(34,197,94,0.1)' : 'rgba(245,158,11,0.1)', color: ggufServerUrl ? '#4ade80' : '#fbbf24', cursor: (ggufStarting || !ggufPath) ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
              {ggufStarting ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Başlatılıyor…</> : ggufServerUrl ? '✅ Sunucu Aktif' : '▶ Başlat'}
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 4 }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: ggufServerUrl ? '#22c55e' : '#f59e0b', boxShadow: ggufServerUrl ? '0 0 6px #22c55e88' : 'none' }} />
              <span style={{ fontSize: 11, color: ggufServerUrl ? '#4ade80' : '#94a3b8' }}>{ggufServerUrl ? `localhost:${ggufPort}` : 'Kapalı'}</span>
            </div>
          </>)}
        </div>

        {connectError && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>{connectError}</div>}
        {ggufError   && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>{ggufError}</div>}

        {chatMode === 'lms' && !connected && (
          <div style={{ marginTop: 10, fontSize: 11, color: '#94a3b8', background: 'rgba(99,102,241,0.04)', borderRadius: 8, padding: '8px 12px', border: '1px solid rgba(99,102,241,0.1)', lineHeight: 1.65 }}>
            LM Studio → <strong style={{ color: '#818cf8' }}>Developer</strong> sekmesi → <strong style={{ color: '#818cf8' }}>Start Server</strong> (port 1234) → "Bağlan". İstediğiniz modeli LM Studio'dan yükleyin.
          </div>
        )}
        {chatMode === 'gguf' && !ggufServerUrl && (
          <div style={{ marginTop: 10, fontSize: 11, color: '#94a3b8', background: 'rgba(245,158,11,0.04)', borderRadius: 8, padding: '8px 12px', border: '1px solid rgba(245,158,11,0.12)', lineHeight: 1.65 }}>
            <strong style={{ color: '#fbbf24' }}>GGUF Direct:</strong> System &amp; Models sayfasından GGUF indirin → Dosya yolunu girin → "Başlat". llama-server PATH'te kurulu olmalı. <br />
            <span style={{ color: '#64748b' }}>İndir: <a href="https://github.com/ggerganov/llama.cpp/releases" target="_blank" rel="noreferrer" style={{ color: '#818cf8' }}>llama.cpp Releases</a></span>
          </div>
        )}
        {/* 2.1 — Context Memory indicator + management */}
        <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
          <button onClick={() => setCtxMemoryOpen(v => !v)}
            style={{ padding: '4px 11px', borderRadius: 7, border: `1px solid ${ctxMemoryEnabled && contextMemory.length > 0 ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.08)'}`, background: ctxMemoryEnabled && contextMemory.length > 0 ? 'rgba(34,197,94,0.06)' : 'transparent', color: ctxMemoryEnabled && contextMemory.length > 0 ? '#4ade80' : '#4b5563', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5, transition: 'all 0.13s' }}>
            <MemoryStick size={12} />
            Bellek {contextMemory.length > 0 ? `(${Math.min(contextMemory.length, ctxMemoryMax)})` : ''}
          </button>
          {ctxMemoryEnabled && contextMemory.length > 0 && (
            <span style={{ fontSize: 10, color: '#22c55e' }}>
              {Math.min(contextMemory.length, ctxMemoryMax)} tarama hatırlanıyor
            </span>
          )}
        </div>

        {/* 2.1 — Context Memory expanded panel */}
        {ctxMemoryOpen && (
          <div style={{ marginTop: 4, borderRadius: 9, padding: '10px 14px', background: 'rgba(34,197,94,0.03)', border: '1px solid rgba(34,197,94,0.15)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#4ade80' }}>Bağlamsal Bellek (Context Memory)</span>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <label style={{ fontSize: 10, color: '#64748b', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                  <input type="checkbox" checked={ctxMemoryEnabled} onChange={e => setCtxMemoryEnabled(e.target.checked)}
                    style={{ width: 13, height: 13, cursor: 'pointer' }} />
                  Aktif
                </label>
                <span style={{ fontSize: 10, color: '#4b5563' }}>Max:</span>
                <select value={ctxMemoryMax} onChange={e => setCtxMemoryMax(parseInt(e.target.value))}
                  style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 5, padding: '2px 6px', fontSize: 10, color: '#e2e8f0', outline: 'none' }}>
                  {[1,2,3,5,8,10,15,20].map(n => <option key={n} value={n}>{n}</option>)}
                </select>
                <button onClick={() => setContextMemory([])}
                  style={{ padding: '2px 8px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.06)', color: '#f87171', cursor: 'pointer', fontSize: 9, fontWeight: 600 }}>
                  Temizle
                </button>
              </div>
            </div>
            {contextMemory.length === 0 ? (
              <div style={{ fontSize: 10, color: '#374151', textAlign: 'center', padding: 8 }}>Henüz bellek yok — bir dosya tarayın, otomatik kaydedilir.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 160, overflowY: 'auto' }}>
                {contextMemory.slice(0, ctxMemoryMax).map((m, i) => (
                  <div key={m.sha256 || i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 5, background: 'rgba(0,0,0,0.15)', fontSize: 10, fontFamily: 'monospace' }}>
                    <span style={{ color: '#4ade80', fontWeight: 600, minWidth: 14 }}>#{i + 1}</span>
                    <span style={{ color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.fileName}</span>
                    <span style={{ color: m.riskScore > 60 ? '#f87171' : m.riskScore > 30 ? '#fbbf24' : '#4ade80' }}>R:{m.riskScore ?? '?'}</span>
                    <span style={{ color: '#64748b' }}>{m.arch}</span>
                    {m.denuvo && <span style={{ color: '#f87171', fontSize: 8, background: 'rgba(248,113,113,0.1)', padding: '0 4px', borderRadius: 3 }}>DEN</span>}
                    {m.vmp && <span style={{ color: '#e879f9', fontSize: 8, background: 'rgba(232,121,249,0.1)', padding: '0 4px', borderRadius: 3 }}>VMP</span>}
                    <button onClick={() => setContextMemory(prev => prev.filter(x => x.sha256 !== m.sha256))}
                      style={{ border: 'none', background: 'transparent', color: '#374151', cursor: 'pointer', padding: 0, lineHeight: 1 }}>
                      <X size={10} />
                    </button>
                  </div>
                ))}
              </div>
            )}
            {!ctxMemoryEnabled && contextMemory.length > 0 && (
              <div style={{ fontSize: 10, color: '#f59e0b', marginTop: 6 }}>⚠ Bellek devre dışı — tarama geçmişi system prompt'a eklenmeyecek.</div>
            )}
          </div>
        )}
      </div>{/* end connection bar */}
      {/* — Messages — */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* 33 — Context window uyarısı */}
        {messages.length >= 15 && !streaming && (
          <div style={{ borderRadius: 9, padding: '9px 14px', background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.22)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <AlertTriangle size={14} color="#fbbf24" style={{ flexShrink: 0 }} />
            <span style={{ fontSize: 11, color: '#92400e', flex: 1 }}>Konuşma <strong style={{ color: '#fbbf24' }}>{messages.length} mesaja</strong> ula?t? — context window dolabilir, yanıtlar kayabilir.</span>
            <button onClick={summarizeConversation}
              style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: '#fbbf24', cursor: 'pointer', fontSize: 10, fontWeight: 600, whiteSpace: 'nowrap' }}>
              Özetle & Temizle
            </button>
          </div>
        )}

        {/* Context Tray — multi-select data sources */}
        {chatContexts.length > 0 && (
          <div style={{ borderRadius: 10, padding: '8px 12px', background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.15)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Layers size={12} color="#818cf8" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#818cf8' }}>Bağlam Kaynakları</span>
                <span style={{ fontSize: 9, color: '#4b5563' }}>({chatContexts.filter(c => c._selected).length}/{chatContexts.length} seçili)</span>
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <button onClick={() => setChatContexts(prev => prev.map(c => ({ ...c, _selected: true })))}
                  style={{ padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer', fontSize: 9 }}>
                  Tümünü Seç
                </button>
                <button onClick={() => setChatContexts(prev => prev.map(c => ({ ...c, _selected: false })))}
                  style={{ padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 9 }}>
                  Hiçbiri
                </button>
                <button onClick={() => {
                  const merged = buildSelectedContextPrompt();
                  if (merged) setInput(merged + '\n\nYukarıdaki tüm verileri birlikte analiz et. Her kaynağı açıkla ve aralarındaki ilişkileri belirle.');
                }}
                  disabled={chatContexts.filter(c => c._selected).length === 0}
                  style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.08)', color: chatContexts.filter(c => c._selected).length > 0 ? '#a78bfa' : '#374151', cursor: chatContexts.filter(c => c._selected).length > 0 ? 'pointer' : 'not-allowed', fontSize: 9, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 }}>
                  <Send size={8} /> Seçilenleri Yükle
                </button>
                {/* 2.2 — Compare button (appears when 2+ scan sources selected) */}
                {chatContexts.filter(c => c._selected && (c.type === 'scanner' || c.type === 'pe_analyst')).length >= 2 && (
                  <button onClick={() => {
                    const comparables = chatContexts.filter(c => c._selected && (c.type === 'scanner' || c.type === 'pe_analyst'));
                    const merged = comparables.map((ctx, i) => `─── Binary ${i + 1}: ${ctx.fileName || '?'} ───\n${formatContextItem(ctx)}`).join('\n\n');
                    setInput(merged + '\n\nBu iki binary arasındaki farkları ve benzerlikleri detaylıca karşılaştır. Section yapıları, import tabloları, koruma mekanizmaları, entropi değerleri ve risk skorları açısından analiz et.');
                  }}
                    style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#fbbf24', cursor: 'pointer', fontSize: 9, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 }}>
                    <Microscope size={8} /> Karşılaştır
                  </button>
                )}
                <button onClick={() => setChatContexts([])}
                  style={{ padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.15)', background: 'transparent', color: '#f87171', cursor: 'pointer', fontSize: 9 }}>
                  Temizle
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              {chatContexts.map(ctx => (
                <div key={ctx._id} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 6,
                  border: `1px solid ${ctx._selected ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`,
                  background: ctx._selected ? 'rgba(99,102,241,0.1)' : 'rgba(255,255,255,0.02)',
                  cursor: 'pointer', transition: 'all 0.12s', userSelect: 'none' }}
                  onClick={() => toggleContext(ctx._id)}>
                  <input type="checkbox" checked={ctx._selected} readOnly
                    style={{ width: 11, height: 11, cursor: 'pointer', accentColor: '#6366f1' }} />
                  <span style={{ fontSize: 10, color: ctx._selected ? '#c7d2fe' : '#4b5563', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {contextLabel(ctx)}
                  </span>
                  <button onClick={(e) => { e.stopPropagation(); removeContext(ctx._id); }}
                    style={{ border: 'none', background: 'transparent', color: '#374151', cursor: 'pointer', padding: 0, lineHeight: 1, display: 'flex' }}>
                    <X size={9} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {chatContexts.length > 0 && messages.length === 0 && !streaming && (
          <div style={{ borderRadius: 10, padding: '10px 14px', background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.2)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <MessageSquare size={14} color="#a78bfa" style={{ flexShrink: 0 }} />
            <div style={{ fontSize: 11, color: '#6b7280' }}>
              <strong style={{ color: '#a78bfa' }}>{chatContexts.filter(c => c._selected).length} kaynak</strong> seçili — textarea dolduruldu, gönder butonuna bas. Seçimi değiştirip "Seçilenleri Yükle" ile yeniden oluşturabilirsin.
            </div>
          </div>
        )}
        {messages.length === 0 && !streaming && chatContexts.length === 0 && (
          <div style={{ textAlign: 'center', padding: '64px 0' }}>
            <MessageSquare size={40} color="#1e2330" style={{ margin: '0 auto 14px', display: 'block' }} />
            <div style={{ fontSize: 14, color: '#2d3748' }}>Henüz mesaj yok</div>
            <div style={{ fontSize: 12, color: '#1e2330', marginTop: 5 }}>LM Studio'da bir model yükleyin, sunucuyu başlatın, bağlanın</div>
          </div>
        )}

        {/* 2.4 — IOC extraction panel */}
        {extractedIOCs.length > 0 && (
          <div style={{ borderRadius: 10, padding: '8px 12px', background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => setIocPanelOpen(v => !v)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <AlertTriangle size={12} color="#f87171" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#f87171' }}>IOC Tespiti</span>
                <span style={{ fontSize: 9, color: '#4b5563', background: 'rgba(239,68,68,0.1)', padding: '1px 6px', borderRadius: 4 }}>
                  {extractedIOCs.length} bulgu
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <button onClick={(e) => {
                  e.stopPropagation();
                  const yaraStrings = extractedIOCs.map((ioc, idx) => {
                    if (ioc.type.startsWith('hash')) return `    $hash_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'ip') return `    $ip_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'domain') return `    $domain_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'url') return `    $url_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'path') return `    $path_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'registry') return `    $reg_${idx} = "${ioc.value}"`;
                    return null;
                  }).filter(Boolean).join('\n');
                  const rule = `rule AI_Extracted_IOCs {\n  meta:\n    author = "Dissect AI"\n    date = "${new Date().toISOString().slice(0,10)}"\n    description = "Auto-generated from AI chat IOC extraction"\n  strings:\n${yaraStrings}\n  condition:\n    any of them\n}`;
                  setInput(rule);
                }}
                  style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.06)', color: '#fbbf24', cursor: 'pointer', fontSize: 9, display: 'flex', alignItems: 'center', gap: 3 }}>
                  YARA Dönüştür
                </button>
                <button onClick={(e) => {
                  e.stopPropagation();
                  const text = extractedIOCs.map(ioc => `[${ioc.type}] ${ioc.value}`).join('\n');
                  navigator.clipboard.writeText(text);
                }}
                  style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 9, display: 'flex', alignItems: 'center', gap: 3 }}>
                  <Copy size={8} /> Kopyala
                </button>
                <ChevronDown size={12} color="#4b5563" style={{ transform: iocPanelOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
              </div>
            </div>
            {iocPanelOpen && (
              <div style={{ marginTop: 8, maxHeight: 200, overflow: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <th style={{ textAlign: 'left', padding: '3px 8px', color: '#4b5563', fontWeight: 600 }}>Tip</th>
                      <th style={{ textAlign: 'left', padding: '3px 8px', color: '#4b5563', fontWeight: 600 }}>Değer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {extractedIOCs.map((ioc, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '3px 8px', color: ioc.type.startsWith('hash') ? '#fbbf24' : ioc.type === 'ip' ? '#f87171' : ioc.type === 'domain' ? '#fb923c' : ioc.type === 'url' ? '#818cf8' : '#4ade80' }}>
                          {{ 'hash-md5': 'MD5', 'hash-sha1': 'SHA1', 'hash-sha256': 'SHA256', ip: 'IP', domain: 'Domain', url: 'URL', path: 'Dosya Yolu', registry: 'Registry' }[ioc.type] || ioc.type}
                        </td>
                        <td style={{ padding: '3px 8px', color: '#9ca3af', fontFamily: 'monospace', wordBreak: 'break-all' }}>{ioc.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {messages.map((msg, i) => {
          // 2.5 — Parse confidence score from assistant messages
          let msgContent = msg.content;
          let confidence = null;
          if (msg.role === 'assistant') {
            const confMatch = msgContent.match(/\[CONFIDENCE:(\d{1,3})%?\]/i);
            if (confMatch) {
              confidence = parseInt(confMatch[1]);
              msgContent = msgContent.replace(/\n?\[CONFIDENCE:\d{1,3}%?\]/gi, '').trim();
            }
          }
          const confColor = confidence != null ? (confidence >= 80 ? '#22c55e' : confidence >= 50 ? '#eab308' : '#ef4444') : null;
          return (
          <div key={i} style={{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start', alignItems: 'flex-start', gap: 10 }}>
            {msg.role === 'assistant' && (
              <div style={{ width: 30, height: 30, borderRadius: 9, background: 'rgba(139,92,246,0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                <Bot size={15} color="#a78bfa" />
              </div>
            )}
            <div style={{ maxWidth: '74%', padding: '10px 15px', borderRadius: msg.role === 'user' ? '14px 14px 4px 14px' : '14px 14px 14px 4px', background: msg.role === 'user' ? 'rgba(99,102,241,0.16)' : 'rgba(255,255,255,0.038)', border: `1px solid ${msg.role === 'user' ? 'rgba(99,102,241,0.28)' : 'rgba(255,255,255,0.07)'}` }}>
              {msg.role === 'user'
                ? <div style={{ fontSize: 13, color: '#c7d2fe', lineHeight: 1.65, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div>
                : <MdText text={msgContent} />
              }
              {/* 2.5 — Confidence badge */}
              {msg.role === 'assistant' && confidence != null && (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, marginTop: 8, padding: '3px 10px', borderRadius: 6, border: `1px solid ${confColor}33`, background: `${confColor}0d` }}>
                  <div style={{ width: 7, height: 7, borderRadius: '50%', background: confColor }} />
                  <span style={{ fontSize: 10, fontWeight: 600, color: confColor }}>Güven: %{confidence}</span>
                  <span style={{ fontSize: 9, color: '#4b5563' }}>
                    {confidence >= 80 ? '— Yüksek olasılıkla' : confidence >= 50 ? '— Orta kesinlik' : '— Düşük güven'}
                  </span>
                </div>
              )}
              {/* 31 — Follow-up suggestions on last assistant message */}
              {msg.role === 'assistant' && i === messages.length - 1 && !streaming && (
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 10, paddingTop: 9, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                  {(FOLLOWUP_BY_MODE[mode] || FOLLOWUP_BY_MODE['analyze']).map(s => (
                    <button key={s} onClick={() => setInput(s)}
                      style={{ padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(139,92,246,0.2)', background: 'rgba(139,92,246,0.05)', color: '#6b7280', cursor: 'pointer', fontSize: 10, transition: 'all 0.12s' }}
                      onMouseEnter={e => { e.currentTarget.style.color = '#a78bfa'; e.currentTarget.style.borderColor = 'rgba(139,92,246,0.4)'; }}
                      onMouseLeave={e => { e.currentTarget.style.color = '#6b7280'; e.currentTarget.style.borderColor = 'rgba(139,92,246,0.2)'; }}>
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {msg.role === 'user' && (
              <div style={{ width: 30, height: 30, borderRadius: 9, background: 'rgba(99,102,241,0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1, fontSize: 13, color: '#818cf8', fontWeight: 700 }}>S</div>
            )}
          </div>
          );
        })}

        {streaming && (
          <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'flex-start', gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 9, background: 'rgba(139,92,246,0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
              <Bot size={15} color="#a78bfa" />
            </div>
            <div style={{ maxWidth: '74%', padding: '10px 15px', borderRadius: '14px 14px 14px 4px', background: 'rgba(255,255,255,0.038)', border: '1px solid rgba(255,255,255,0.07)' }}>
              {streamContent
                ? <><MdText text={streamContent} /><span style={{ display: 'inline-block', width: 2, height: 13, background: '#a78bfa', marginLeft: 2, verticalAlign: 'middle', animation: 'cursor-blink 1s steps(1) infinite' }} /></>
                : <span style={{ fontSize: 13, color: '#374151' }}>Düşünüyor⬦<span style={{ display: 'inline-block', width: 2, height: 13, background: '#a78bfa', marginLeft: 2, verticalAlign: 'middle', animation: 'cursor-blink 1s steps(1) infinite' }} /></span>
              }
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* —� Input —� */}
      <div style={{ padding: '10px 20px 16px', borderTop: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        {/* Quick Actions — 36 */}
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
          {QUICK_PROMPTS.map(p => (
            <button key={p.label} onClick={() => setInput(p.text)} disabled={streaming}
              style={{ padding: '3px 9px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.03)', color: '#374151', cursor: streaming ? 'not-allowed' : 'pointer', fontSize: 10, transition: 'all 0.12s' }}
              onMouseEnter={e => { if (!streaming) { e.currentTarget.style.color = '#818cf8'; e.currentTarget.style.borderColor = 'rgba(99,102,241,0.3)'; } }}
              onMouseLeave={e => { e.currentTarget.style.color = '#374151'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'; }}>
              {p.label}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
            placeholder={connected ? `${selectedModel} — Mesaj yaz (Enter = gönder, Shift+Enter = yeni satır)` : 'Önce LM Studio\'ya bağlanın⬦'}
            disabled={streaming}
            rows={2}
            style={{ flex: 1, background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.09)', borderRadius: 10, padding: '10px 13px', fontSize: 13, color: '#e2e8f0', outline: 'none', resize: 'none', fontFamily: 'inherit', lineHeight: 1.5 }}
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <button onClick={sendMessage} disabled={streaming || !input.trim() || !isReady}
              style={{ width: 44, height: 44, borderRadius: 10, border: 'none', background: (!streaming && input.trim() && connected && selectedModel) ? 'rgba(99,102,241,0.22)' : 'rgba(99,102,241,0.06)', color: (!streaming && input.trim() && connected && selectedModel) ? '#818cf8' : '#2d3748', cursor: (!streaming && input.trim() && connected && selectedModel) ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.13s' }}>
              <Send size={17} />
            </button>
            {messages.length > 0 && !streaming && (
              <button onClick={() => setMessages([])}
                style={{ width: 44, height: 22, borderRadius: 7, border: '1px solid rgba(255,255,255,0.06)', background: 'transparent', color: '#2d3748', cursor: 'pointer', fontSize: 9, fontWeight: 600, textTransform: 'uppercase' }}>
                Sil
              </button>
            )}
          </div>
        </div>
      </div>


































































































































































































































    </div>
  );
}

const QUICK_PROMPTS = [
  { label: '🛡 Koruma mekanizması',  text: 'Bu binary\'deki koruma mekanizmalarını detaylıca açıkla. Hangi katmanlar var ve nasıl çalışıyor?' },
  { label: '⚠️ Risk faktörleri',     text: 'Bu analizin tüm risk faktörlerini öncelik sırasına göre listele ve her birini açıkla.' },
  { label: '✎ Import analizi',       text: 'Import tablosundaki en şüpheli fonksiyonları listele. Anti-debug, network, crypto olanları özellikle işaretle.' },
  { label: '📊 Entropy yorumu',       text: 'Yüksek entropi değerleri ne anlama gelir? Bu binary\'de packer veya şifreleme var mı?' },
  { label: '🗺 Nereden başlamalıyım?',   text: 'Bu binary\'yi tersine mühendislik ile incelemek istesem nereden başlamalıyım? Adım adım anlat.' },
  { label: '🧠 Hipotez üret',         text: 'Mevcut verilere dayanarak bu binary\'nin amacı ve davranışı hakkında 3 farklı hipotez üret.' },
  { label: '🔍 Anti-debug detay',     text: 'Tespit edilen anti-debug tekniklerini açıkla. Her biri debugger\'ı nasıl etkiler?' },
  { label: '📋 Özet rapor',           text: 'Tüm bulguları kısa ve net bir executive summary olarak özetle. Teknik olmayan bir okuyucuya hitap et.' },
  { label: '🎯 YARA kuralı üret',      text: 'Bu PE analizindeki benzersiz özelliklere dayanarak tam ve geçerli YARA kuralları oluştur. Meta, strings ve condition bölümlerini dahil et. SHA256, import imzaları, section özellikleri ve şüpheli stringleri kullan. Sadece geçerli YARA sözdizimi çıktısında ver.' },
];

const FOLLOWUP_BY_MODE = {
  explain:    ['Bu davranışı daha basit anlat', 'Benzer bir örnek ver', 'Hangi araçlarla incelenebilir?'],
  analyze:    ['Ba?ka hangi protectionlar olabilir?', 'Risk skorunu detaylandır', 'False positive olabilir mi?'],
  guide:      ['Bir sonraki adım ne?', 'Hangi aracı kullanmalıyım?', 'Nereye dikkat etmeliyim?'],
  hypothesis: ['Bu hipotezi nasıl do?rularım?', 'Alternatif senaryo var mı?', 'En olası hangisi ve neden?'],
};

// —�—�—� AI Modes (CoreXAI 2 Blueprint) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

const AI_MODES = [
  {
    id: 'explain',
    label: 'Explain',
    color: '#818cf8',
    bg: 'rgba(99,102,241,0.10)',
    border: 'rgba(99,102,241,0.28)',
    desc: 'Describe behavior & logic',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in EXPLAIN mode. Your goal is to clearly describe what the analyzed binary/code does, how it behaves, what patterns and functions are present, and what the overall logic means. Be structured, educational, and clear. Highlight important patterns. Do NOT provide direct bypass, crack, or patch solutions — focus on understanding and explanation.',
  },
  {
    id: 'analyze',
    label: 'Analyze',
    color: '#f59e0b',
    bg: 'rgba(245,158,11,0.08)',
    border: 'rgba(245,158,11,0.28)',
    desc: 'Detect patterns & classify',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in ANALYZE mode. Your goal is to detect patterns, identify protection mechanisms (Denuvo, VMProtect, Themida, etc.), classify suspicious behaviors, assess risk, and build a technical profile of the binary. Be precise and technical. List your findings clearly and explain why each one matters. Do NOT provide direct bypass or cracking solutions.',
  },
  {
    id: 'guide',
    label: 'Guide',
    color: '#4ade80',
    bg: 'rgba(34,197,94,0.07)',
    border: 'rgba(34,197,94,0.22)',
    desc: 'Step-by-step mentoring',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in GUIDE mode. Act as a mentor and guide the user step-by-step through understanding the binary. Ask clarifying questions. Break the problem into manageable steps. Suggest what to investigate next. Use the Socratic method — help the user discover answers themselves rather than giving direct solutions. Do NOT provide bypass, crack, or patch solutions.',
  },
  {
    id: 'hypothesis',
    label: 'Hypothesis',
    color: '#f472b6',
    bg: 'rgba(244,114,182,0.07)',
    border: 'rgba(244,114,182,0.22)',
    desc: 'Generate assumptions',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in HYPOTHESIS mode. Generate educated assumptions about the binary based on available evidence. Use phrases like "This might indicate...", "A likely hypothesis is...", "This pattern could suggest...". Build a theory from the data. Be speculative but grounded in the evidence. Do NOT provide direct bypass or cracking solutions.',
  },
  {
    id: 'yara',
    label: 'YARA',
    color: '#34d399',
    bg: 'rgba(52,211,153,0.07)',
    border: 'rgba(52,211,153,0.22)',
    desc: 'Generate YARA detection rules',
    system: 'You are Dissect, a local AI binary analysis assistant. You are in YARA mode. Based on the provided PE analysis data, generate professional, complete, and immediately usable YARA rules. Each rule must include: rule name (snake_case), meta section (description, author="Dissect", date, hash), strings section (hex byte patterns, notable text strings, imports), and a condition section. Use unique indicators from the analysis such as section characteristics, import signatures, entropy values, and suspicious strings. Output only valid YARA syntax with comments. Do NOT add any prose outside the rule blocks.',
  },
];

// ══════════════════════════════════════════════════════════════════════
// FAZ 5 — Plugin Ekosistemi
// ══════════════════════════════════════════════════════════════════════

// ── 5.3 Plugin API ────────────────────────────────────────────────

const DissectPluginAPI = {
  onScan(fn)          { if (typeof fn === 'function') _pluginHooks.onScan.push(fn); },
  onPatch(fn)         { if (typeof fn === 'function') _pluginHooks.onPatch.push(fn); },
  onDisassemble(fn)   { if (typeof fn === 'function') _pluginHooks.onDisassemble.push(fn); },
  registerCommand(label, fn) { if (label && typeof fn === 'function') _pluginHooks.commands.push({ label, fn }); },
  registerView(id, label, renderFn) { if (id && typeof renderFn === 'function') _pluginHooks.views.push({ id, label, renderFn }); },
  accessAI(prompt)    { _pluginHooks.aiQueries.push(prompt); return prompt; },
  log(...args)        { console.log('[Plugin]', ...args); },
  getHistory()        { try { return JSON.parse(localStorage.getItem('dissect_scan_history') || '[]'); } catch { return []; } },
};

// ── 5.1 Plugin Loader — sandboxed execution ──────────────────────
const PLUGIN_STORE_KEY = 'dissect_plugins_v2';
function loadInstalledPlugins() { try { return JSON.parse(localStorage.getItem(PLUGIN_STORE_KEY) || '[]'); } catch { return []; } }
function saveInstalledPlugins(list) { localStorage.setItem(PLUGIN_STORE_KEY, JSON.stringify(list)); }
function executePluginCode(code, pluginId) {
  try {
    const sandbox = new Function('Dissect', 'console', '"use strict";\n' + code);
    const safeConsole = { log: (...a) => console.log('[Plugin:' + pluginId + ']', ...a), warn: (...a) => console.warn('[Plugin:' + pluginId + ']', ...a), error: (...a) => console.error('[Plugin:' + pluginId + ']', ...a) };
    sandbox(DissectPluginAPI, safeConsole);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
}

// ── 5.4 Example Plugins ─────────────────────────────────────────

const EXAMPLE_PLUGINS = [
  {
    id: 'string_decoder', name: 'String Decoder', version: '1.0.0', author: 'Dissect Team',
    desc: 'Base64, XOR, ROT13 encoded stringleri otomatik decode eder.',
    stars: 4.7, downloads: 1240, tags: ['strings', 'decoder', 'obfuscation'],
    code: `
Dissect.onScan(function(result) {
  var decoded = [];
  (result.strings || []).forEach(function(s) {
    var text = s.text || s;
    if (/^[A-Za-z0-9+\\/]{16,}={0,2}$/.test(text)) {
      try { var d = atob(text); if (/^[\\x20-\\x7e]+$/.test(d)) decoded.push({original:text,method:'Base64',decoded:d}); } catch(e){}
    }
    if (/^[A-Za-z]{8,}$/.test(text)) {
      var r = text.replace(/[a-zA-Z]/g, function(c) { return String.fromCharCode((c<='Z'?90:122)>=(c.charCodeAt(0)+13)?c.charCodeAt(0)+13:c.charCodeAt(0)-13); });
      if (r !== text && /(?:http|dll|exe|cmd|reg|key)/i.test(r)) decoded.push({original:text,method:'ROT13',decoded:r});
    }
  });
  if (decoded.length > 0) Dissect.log('Decoded ' + decoded.length + ' strings:', decoded);
});
Dissect.registerCommand('Decode Strings', function() { Dissect.log('String decoder active'); });`,
  },
  {
    id: 'crypto_identifier', name: 'Crypto Identifier', version: '1.0.0', author: 'Dissect Team',
    desc: 'Kriptografik sabit degerlerden (magic numbers) algoritma tespiti.',
    stars: 4.5, downloads: 890, tags: ['crypto', 'detection', 'constants'],
    code: `
var CRYPTO_SIGS = [
  {name:'AES S-Box',hex:'637c777bf26b6fc5',algo:'AES'},
  {name:'SHA-256 Init',hex:'6a09e667bb67ae85',algo:'SHA-256'},
  {name:'MD5 T[1]',hex:'d76aa478',algo:'MD5'},
  {name:'Blowfish P',hex:'243f6a8885a308d3',algo:'Blowfish'},
  {name:'CRC32 Poly',hex:'edb88320',algo:'CRC32'},
  {name:'TEA Delta',hex:'9e3779b9',algo:'TEA/XTEA'},
];
Dissect.onScan(function(result) {
  var found = [];
  var allText = (result.strings||[]).map(function(s){return(s.text||s).toLowerCase();}).join(' ');
  CRYPTO_SIGS.forEach(function(sig){if(allText.indexOf(sig.hex)>=0) found.push(sig);});
  (result.imports||[]).forEach(function(imp){
    var dll=(imp.dll||'').toLowerCase();
    if(dll.indexOf('bcrypt')>=0||dll.indexOf('ncrypt')>=0) found.push({name:dll,algo:'Windows CNG'});
    if(dll.indexOf('crypt32')>=0) found.push({name:dll,algo:'CryptoAPI'});
  });
  if(found.length>0) Dissect.log('Crypto detected:',found);
});
Dissect.registerCommand('Crypto Report', function(){Dissect.log('Crypto identifier active');});`,
  },
  {
    id: 'import_highlighter', name: 'Import Highlighter', version: '1.0.0', author: 'Dissect Team',
    desc: 'Tehlikeli Windows API cagilarini tespit edip kategorize eder.',
    stars: 4.8, downloads: 1580, tags: ['imports', 'security', 'api'],
    code: `
var DANGEROUS={
  'Injection':['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtCreateThreadEx','QueueUserAPC','SetWindowsHookEx'],
  'Execution':['ShellExecuteA','ShellExecuteW','WinExec','CreateProcessA','CreateProcessW'],
  'Persistence':['RegSetValueExA','RegSetValueExW','CreateServiceA','CreateServiceW'],
  'Anti-Debug':['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess'],
  'Network':['InternetOpenA','HttpSendRequestA','URLDownloadToFileA','WSAStartup','connect','send','recv'],
};
Dissect.onScan(function(result){
  var hits={};
  (result.imports||[]).forEach(function(imp){
    (imp.functions||[]).forEach(function(fn){
      Object.keys(DANGEROUS).forEach(function(cat){
        if(DANGEROUS[cat].some(function(api){return fn.indexOf(api)>=0;})){
          if(!hits[cat])hits[cat]=[];
          hits[cat].push(fn+' ('+((imp.dll)||'?')+')');
        }
      });
    });
  });
  var total=Object.values(hits).reduce(function(s,a){return s+a.length;},0);
  if(total>0) Dissect.log('Dangerous APIs: '+total+' hits',hits);
});
Dissect.registerCommand('Show Dangerous APIs', function(){Dissect.log('Import highlighter active');});`,
  },
];

// ── Builtin display list ─────────────────────────────────────────

const BUILTIN_PLUGINS = [
  { id:'pe_scanner',  name:'PE Scanner',       desc:'PE header, entropy, section, string, import analizi.', icon:<ShieldAlert size={15}/>, version:'2.0.0', status:'active', builtin:true },
  { id:'hex_patcher', name:'Hex Patcher',       desc:'Binary offset yamalama, NOP injection, backup.',      icon:<Binary size={15}/>,      version:'2.0.0', status:'active', builtin:true },
  { id:'yara_engine', name:'YARA Engine',       desc:'JS tabanli davranissal kural motoru, 15 kural.',      icon:<FileSearch size={15}/>,  version:'1.0.0', status:'active', builtin:true },
  { id:'ai_analyst',  name:'AI Analyst',        desc:'LM Studio streaming PE analiz entegrasyonu.',         icon:<Bot size={15}/>,         version:'2.2.0', status:'active', builtin:true },
  { id:'binary_diff', name:'Binary Diff',       desc:'Iki PE dosyasini yan yana karsilastirma.',            icon:<Layers size={15}/>,      version:'1.0.0', status:'active', builtin:true },
  { id:'hex_viewer',  name:'Hex Region Viewer', desc:'Bolge bazli ham hex okuma (Rust destekli).',          icon:<Terminal size={15}/>,    version:'1.0.0', status:'active', builtin:true },
  { id:'sig_scanner', name:'Packer Signatures', desc:'UPX/MPRESS/ASPack/Petite imza tanima.',               icon:<Cpu size={15}/>,         version:'1.0.0', status:'active', builtin:true },
];

// ── 5.2 Plugin Marketplace + Full UI ─────────────────────────────

function PluginPage() {
  const [tab, setTab] = useState('installed');
  const [installed, setInstalled] = useState(loadInstalledPlugins);
  const [customCode, setCustomCode] = useState('');
  const [customName, setCustomName] = useState('');
  const [loadMsg, setLoadMsg] = useState('');
  const [msgType, setMsgType] = useState('info');
  const [search, setSearch] = useState('');
  const [ratings, setRatings] = useState(() => { try { return JSON.parse(localStorage.getItem('dissect_plugin_ratings') || '{}'); } catch { return {}; } });

  const showMsg = (msg, type = 'info') => { setLoadMsg(msg); setMsgType(type); setTimeout(() => setLoadMsg(''), 4000); };

  useEffect(() => { installed.forEach(p => { if (p.enabled) executePluginCode(p.code, p.id); }); }, []);

  const installPlugin = (plugin) => {
    if (installed.find(p => p.id === plugin.id)) { showMsg(plugin.name + ' zaten yuklu.', 'error'); return; }
    const entry = { id: plugin.id, name: plugin.name, version: plugin.version, author: plugin.author || 'Unknown', desc: plugin.desc, code: plugin.code, enabled: true, installedAt: new Date().toISOString(), tags: plugin.tags || [] };
    const res = executePluginCode(entry.code, entry.id);
    if (res.success) { const u = [entry, ...installed]; setInstalled(u); saveInstalledPlugins(u); showMsg(plugin.name + ' basariyla kuruldu.', 'success'); }
    else showMsg('Plugin hata: ' + res.error, 'error');
  };
  const uninstallPlugin = (id) => { const u = installed.filter(p => p.id !== id); setInstalled(u); saveInstalledPlugins(u); showMsg('Plugin kaldirildi.', 'info'); };
  const togglePlugin = (id) => {
    const u = installed.map(p => { if (p.id !== id) return p; const ns = !p.enabled; if (ns) executePluginCode(p.code, p.id); return { ...p, enabled: ns }; });
    setInstalled(u); saveInstalledPlugins(u);
  };
  const installCustom = () => {
    if (!customCode.trim()) { showMsg('Kod bos olamaz.', 'error'); return; }
    const id = 'custom_' + Date.now(), name = customName.trim() || 'Custom Plugin';
    const entry = { id, name, version: '1.0.0', author: 'User', desc: 'Kullanici tanimli plugin', code: customCode, enabled: true, installedAt: new Date().toISOString(), tags: ['custom'] };
    const res = executePluginCode(entry.code, entry.id);
    if (res.success) { const u = [entry, ...installed]; setInstalled(u); saveInstalledPlugins(u); setCustomCode(''); setCustomName(''); showMsg(name + ' kuruldu.', 'success'); }
    else showMsg('Hata: ' + res.error, 'error');
  };
  const handleFileLoad = () => {
    const input = document.createElement('input'); input.type = 'file'; input.accept = '.js,.txt';
    input.onchange = async (e) => { const f = e.target.files?.[0]; if (!f) return; setCustomCode(await f.text()); setCustomName(f.name.replace(/\.(js|txt)$/, '')); showMsg(f.name + ' yuklendi.', 'info'); };
    input.click();
  };
  const ratePlugin = (pid, stars) => { const u = { ...ratings, [pid]: stars }; setRatings(u); localStorage.setItem('dissect_plugin_ratings', JSON.stringify(u)); };

  const StarRating = ({ pluginId, readonly, value }) => {
    const v = readonly ? value : (ratings[pluginId] || 0);
    return (<div style={{ display: 'flex', gap: 2 }}>{[1,2,3,4,5].map(s => (<span key={s} onClick={() => !readonly && ratePlugin(pluginId, s)} style={{ cursor: readonly ? 'default' : 'pointer', fontSize: 12, color: s <= v ? '#fbbf24' : '#1f2937' }}>&#9733;</span>))}{!readonly && v > 0 && <span style={{ fontSize: 9, color: '#374151', marginLeft: 4 }}>{v}/5</span>}</div>);
  };
  const TabBtn = ({ id, label, count }) => (
    <button onClick={() => setTab(id)} style={{ fontSize: 11, padding: '6px 14px', borderRadius: '7px 7px 0 0', border: '1px solid ' + (tab === id ? 'rgba(99,102,241,0.3)' : 'rgba(255,255,255,0.04)'), borderBottom: tab === id ? '2px solid #6366f1' : '1px solid rgba(255,255,255,0.04)', background: tab === id ? 'rgba(99,102,241,0.08)' : 'transparent', color: tab === id ? '#818cf8' : '#4b5563', cursor: 'pointer', fontWeight: tab === id ? 700 : 400 }}>
      {label} {count !== undefined && <span style={{ fontSize: 9, opacity: 0.6 }}>({count})</span>}
    </button>
  );
  const PluginCard = ({ p, actions, dimmed }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)', opacity: dimmed ? 0.45 : 1 }}>
      <div style={{ width: 32, height: 32, borderRadius: 8, background: 'rgba(99,102,241,0.09)', border: '1px solid rgba(99,102,241,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#818cf8', flexShrink: 0, fontSize: 14 }}>{p.icon || '🧩'}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{p.name} <span style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace' }}>v{p.version}</span></div>
        <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{p.desc}</div>
        {p.tags && <div style={{ display: 'flex', gap: 4, marginTop: 3 }}>{p.tags.map(t => <span key={t} style={{ fontSize: 8, padding: '1px 6px', borderRadius: 3, background: 'rgba(99,102,241,0.06)', color: '#6366f1', fontWeight: 500 }}>{t}</span>)}</div>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>{actions}</div>
    </div>
  );
  const marketplace = EXAMPLE_PLUGINS.filter(p => !search || p.name.toLowerCase().includes(search.toLowerCase()) || p.tags.some(t => t.includes(search.toLowerCase())));

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Layers size={17} color="#818cf8" /></div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: '#e2e8f0', margin: 0 }}>Plugin Ecosystem</h1>
          </div>
          <p style={{ fontSize: 11, color: '#374151', margin: 0 }}>FAZ 5 — Magaza · Yukleyici · Sandbox API · Hook sistemi</p>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <span style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: 'rgba(34,197,94,0.08)', color: '#4ade80', fontWeight: 600 }}>{installed.filter(p => p.enabled).length} aktif</span>
          <span style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: 'rgba(99,102,241,0.08)', color: '#818cf8', fontWeight: 600 }}>{_pluginHooks.commands.length} cmd</span>
        </div>
      </div>
      {loadMsg && <div style={{ marginBottom: 12, padding: '8px 14px', borderRadius: 8, background: msgType==='success'?'rgba(34,197,94,0.08)':msgType==='error'?'rgba(239,68,68,0.08)':'rgba(99,102,241,0.08)', border: '1px solid '+(msgType==='success'?'rgba(34,197,94,0.2)':msgType==='error'?'rgba(239,68,68,0.2)':'rgba(99,102,241,0.2)'), fontSize: 11, color: msgType==='success'?'#4ade80':msgType==='error'?'#f87171':'#818cf8' }}>{loadMsg}</div>}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <TabBtn id="installed" label="Yuklu" count={installed.length} />
        <TabBtn id="marketplace" label="Magaza" count={EXAMPLE_PLUGINS.length} />
        <TabBtn id="builtin" label="Dahili" count={BUILTIN_PLUGINS.length} />
        <TabBtn id="custom" label="Ozel Plugin Yukle" />
        <TabBtn id="api" label="API Dokumantasyon" />
      </div>

      {/* Installed */}
      {tab === 'installed' && (
        <Card>
          <CardHeader>Kurulu Pluginler — {installed.length}</CardHeader>
          {installed.length === 0 ? (
            <div style={{ padding: '20px 16px', textAlign: 'center', fontSize: 11, color: '#374151' }}>Henuz plugin kurulmamis. Magazadan veya ozel plugin yukleyebilirsiniz.</div>
          ) : installed.map(p => (
            <PluginCard key={p.id} p={p} actions={<>
              <StarRating pluginId={p.id} />
              <button onClick={() => togglePlugin(p.id)} style={{ fontSize: 9, padding: '3px 10px', borderRadius: 5, border: '1px solid '+(p.enabled?'rgba(34,197,94,0.3)':'rgba(239,68,68,0.2)'), background: p.enabled?'rgba(34,197,94,0.08)':'rgba(239,68,68,0.06)', color: p.enabled?'#4ade80':'#f87171', cursor: 'pointer', fontWeight: 600 }}>{p.enabled?'ON':'OFF'}</button>
              <button onClick={() => uninstallPlugin(p.id)} style={{ fontSize: 9, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>X</button>
            </>} />
          ))}
        </Card>
      )}

      {/* Marketplace (5.2) */}
      {tab === 'marketplace' && (
        <Card>
          <CardHeader>Plugin Magazasi</CardHeader>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Plugin ara... (isim veya etiket)" style={{ width: '100%', fontSize: 12, padding: '7px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
          </div>
          {marketplace.map(p => {
            const isInst = installed.find(i => i.id === p.id);
            return (
              <PluginCard key={p.id} p={p} actions={<>
                <div style={{ textAlign: 'right', marginRight: 4 }}>
                  <StarRating pluginId={p.id} readonly value={p.stars} />
                  <div style={{ fontSize: 8, color: '#374151' }}>{p.downloads} indirme</div>
                </div>
                {isInst ? <span style={{ fontSize: 9, padding: '3px 10px', borderRadius: 5, background: 'rgba(34,197,94,0.08)', color: '#4ade80', fontWeight: 700 }}>Yuklu</span>
                  : <button onClick={() => installPlugin(p)} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>Kur</button>}
              </>} />
            );
          })}
        </Card>
      )}

      {/* Built-in */}
      {tab === 'builtin' && (
        <Card>
          <CardHeader>Dahili Moduller — {BUILTIN_PLUGINS.length}</CardHeader>
          <div style={{ padding: '4px 0 8px' }}>
            {BUILTIN_PLUGINS.map(p => (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '9px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <div style={{ width: 30, height: 30, borderRadius: 7, background: 'rgba(99,102,241,0.09)', border: '1px solid rgba(99,102,241,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#818cf8', flexShrink: 0 }}>{p.icon}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{p.name} <span style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace' }}>v{p.version}</span></div>
                  <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{p.desc}</div>
                </div>
                <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, background: 'rgba(34,197,94,0.1)', color: '#4ade80', fontWeight: 700 }}>ACTIVE</span>
                <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: 'rgba(99,102,241,0.1)', color: '#818cf8', fontWeight: 600 }}>built-in</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Custom Plugin Loader (5.1) */}
      {tab === 'custom' && (
        <Card>
          <CardHeader>Ozel Plugin Yukle (5.1)</CardHeader>
          <div style={{ padding: '16px' }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
              <input value={customName} onChange={e => setCustomName(e.target.value)} placeholder="Plugin adi..." style={{ flex: 1, fontSize: 12, padding: '7px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
              <button onClick={handleFileLoad} style={{ fontSize: 11, padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.07)', color: '#818cf8', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}><Download size={13} /> .js Dosyadan Yukle</button>
              <button onClick={installCustom} style={{ fontSize: 11, padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontWeight: 600 }}>Kur</button>
            </div>
            <textarea value={customCode} onChange={e => setCustomCode(e.target.value)} placeholder={'// Plugin kodunuzu buraya yazin veya yukleyin\n// API: Dissect.onScan(fn), Dissect.onPatch(fn),\n// Dissect.onDisassemble(fn), Dissect.registerCommand(label,fn),\n// Dissect.registerView(id,label,renderFn), Dissect.accessAI(prompt),\n// Dissect.log(...), Dissect.getHistory()\n\nDissect.onScan(function(result) {\n  Dissect.log("Scan:", result.fileName, "Risk:", result.riskScore);\n});\nDissect.registerCommand("My Command", function() {\n  Dissect.log("Custom command executed!");\n});'}
              style={{ width: '100%', height: 260, fontSize: 11, fontFamily: 'monospace', padding: '12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', color: '#e5e7eb', outline: 'none', resize: 'vertical', lineHeight: 1.6 }} />
            <div style={{ marginTop: 10, padding: '10px 14px', borderRadius: 8, background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.15)' }}>
              <div style={{ fontSize: 10, color: '#fbbf24', fontWeight: 600, marginBottom: 4 }}>Guvenlik Notu</div>
              <div style={{ fontSize: 10, color: '#92400e', lineHeight: 1.5 }}>Pluginler sandbox ortaminda calisir. Sadece Dissect API ve console objesine erisebilirler. DOM, fetch, localStorage, eval gibi global APIlere erisimleri yoktur.</div>
            </div>
          </div>
        </Card>
      )}

      {/* API Documentation (5.3) */}
      {tab === 'api' && (
        <Card>
          <CardHeader>Plugin API v2.0 (FAZ 5.3)</CardHeader>
          <div style={{ padding: '16px' }}>
            <pre style={{ fontSize: 10, fontFamily: 'monospace', color: '#94a3b8', margin: 0, lineHeight: 1.7, background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, overflowX: 'auto' }}>
{`// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dissect Plugin API v2.0 (FAZ 5)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Hook: tarama sonucu
Dissect.onScan(function(result) {
  // result: {fileName,arch,riskScore,
  //  sections,imports,strings,entropy,
  //  sha256,md5,packers,denuvo,vmp,...}
  console.log('Scan:', result);
});

// Hook: patch uygulandi
Dissect.onPatch(function(info) {
  // info: {offset,oldBytes,newBytes,fileName}
});

// Hook: disassembly
Dissect.onDisassemble(function(data) {
  // data: {address,instructions,functionName}
});

// Komut paleti (Ctrl+K) komutu ekle
Dissect.registerCommand('My Cmd', function() {
  Dissect.log('Executed!');
});

// Ozel panel kaydet
Dissect.registerView('my_view', 'Panel', fn);

// AI'a soru gonder
Dissect.accessAI('prompt text');

// Yardimci
Dissect.log('msg', {data: 123});
var h = Dissect.getHistory(); // read-only

// Plugin Manifest:
// { id, name, version, author, desc,
//   tags, code }
`}
            </pre>
          </div>
        </Card>
      )}

      {/* Plugin-registered views (5.3) */}
      {getPluginViews().length > 0 && (
        <Card style={{ marginTop: 16 }}>
          <CardHeader>Plugin Panelleri ({getPluginViews().length})</CardHeader>
          <div style={{ padding: '8px 16px' }}>
            {getPluginViews().map(v => (
              <div key={v.id} style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 11, color: '#94a3b8' }}>
                <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{v.label}</span>
                <span style={{ fontSize: 9, color: '#374151', marginLeft: 8 }}>ID: {v.id}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── CFG Panel (1.3) ──────────────────────────────────────────────────────────

const CFG_BLOCK_COLORS = {
  entry:  { bg: 'rgba(99,102,241,0.15)',  border: '#6366f1' },
  exit:   { bg: 'rgba(248,113,113,0.15)', border: '#f87171' },
  branch: { bg: 'rgba(251,191,36,0.12)',  border: '#fbbf24' },
  call:   { bg: 'rgba(96,165,250,0.12)',  border: '#60a5fa' },
  normal: { bg: 'rgba(255,255,255,0.04)', border: '#374151' },
};

const CFG_EDGE_COLORS = {
  branch_true:   '#22c55e',
  branch_false:  '#ef4444',
  unconditional: '#f59e0b',
  fallthrough:   '#475569',
  call:          '#60a5fa',
};

function CfgBlockNode({ data }) {
  const colors = CFG_BLOCK_COLORS[data.block_type] || CFG_BLOCK_COLORS.normal;
  return (
    <div style={{
      background: colors.bg,
      border: `1.5px solid ${colors.border}`,
      borderRadius: 6,
      padding: 0,
      minWidth: 220,
      maxWidth: 340,
      fontFamily: '"JetBrains Mono", monospace',
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '4px 8px',
        background: 'rgba(0,0,0,0.25)',
        borderBottom: `1px solid ${colors.border}`,
        display: 'flex', alignItems: 'center', gap: 6,
        fontSize: 9, fontWeight: 700, color: colors.border,
      }}>
        <span>{data.label}</span>
        <span style={{ marginLeft: 'auto', fontSize: 8, color: '#64748b' }}>{data.block_type}</span>
      </div>
      <div style={{ padding: '3px 0', maxHeight: 180, overflowY: 'auto' }}>
        {(data.instructions || []).map((ins, i) => (
          <div key={i} style={{
            display: 'flex', gap: 6, padding: '1px 8px', fontSize: 10, lineHeight: '16px',
            background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
          }}>
            <span style={{ color: '#4b5563', minWidth: 24, flexShrink: 0 }}>{ins.addr?.slice(-4)}</span>
            <span style={{
              fontWeight: 700, minWidth: 32, flexShrink: 0,
              color: ins.kind === 'call' ? '#60a5fa' : ins.kind === 'jmp' ? '#f59e0b' : ins.kind === 'jcc' ? '#fbbf24' : ins.kind === 'ret' ? '#f87171' : ins.kind === 'nop' ? '#374151' : ins.kind === 'cmp' ? '#c084fc' : '#e2e8f0',
            }}>{ins.mnemonic}</span>
            <span style={{ color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ins.operands}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const cfgNodeTypes = { cfgBlock: CfgBlockNode };

function layoutCfgGraph(blocks, edges) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 60, marginx: 30, marginy: 30 });
  g.setDefaultEdgeLabel(() => ({}));

  blocks.forEach(b => {
    const insCount = (b.instructions || []).length;
    const h = Math.min(36 + insCount * 17, 220);
    g.setNode(b.id, { width: 280, height: h });
  });

  edges.forEach(e => {
    g.setEdge(e.source, e.target);
  });

  dagre.layout(g);

  const nodes = blocks.map(b => {
    const pos = g.node(b.id);
    return {
      id: b.id,
      type: 'cfgBlock',
      position: { x: pos.x - 140, y: pos.y - pos.height / 2 },
      data: { ...b },
      style: { width: 280 },
    };
  });

  const flowEdges = edges.map((e, i) => ({
    id: `e${i}`,
    source: e.source,
    target: e.target,
    type: 'smoothstep',
    animated: e.edge_type === 'branch_true' || e.edge_type === 'unconditional',
    label: e.edge_type === 'branch_true' ? 'T' : e.edge_type === 'branch_false' ? 'F' : '',
    labelStyle: { fontSize: 9, fontWeight: 700, fill: CFG_EDGE_COLORS[e.edge_type] || '#475569' },
    style: { stroke: CFG_EDGE_COLORS[e.edge_type] || '#475569', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: CFG_EDGE_COLORS[e.edge_type] || '#475569', width: 14, height: 14 },
  }));

  return { nodes, edges: flowEdges };
}

function CFGPanel({ filePath, funcAddr, funcName, onBlockClick, onClose }) {
  const [cfgData, setCfgData]       = useState(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (!filePath || !funcAddr) return;
    let cancel = false;
    setLoading(true);
    setError(null);
    invoke('get_cfg', { filePath, funcAddr, maxInsns: 1000 })
      .then(r => {
        if (cancel) return;
        setCfgData(r);
        const layout = layoutCfgGraph(r.blocks, r.edges);
        setNodes(layout.nodes);
        setEdges(layout.edges);
      })
      .catch(e => { if (!cancel) setError(String(e)); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [filePath, funcAddr]);

  const handleNodeClick = useCallback((_, node) => {
    if (onBlockClick && node.data?.start_addr) {
      onBlockClick(node.data.start_addr);
    }
  }, [onBlockClick]);

  const proOptions = useMemo(() => ({ hideAttribution: true }), []);

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.2)', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8,
        borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.15)', flexShrink: 0,
      }}>
        <GitBranch size={13} color="#818cf8" />
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0' }}>CFG</span>
        <span style={{ fontSize: 10, color: '#818cf8', fontFamily: 'monospace' }}>{funcName || `sub_${(funcAddr || 0).toString(16).toUpperCase()}`}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          {cfgData && <span style={{ fontSize: 9, color: '#4b5563' }}>{cfgData.blocks.length} blok · {cfgData.edges.length} kenar</span>}
          <button onClick={onClose} style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer' }}>
            <X size={10} />
          </button>
        </div>
      </div>

      {/* Graph area */}
      <div style={{ flex: 1, position: 'relative' }}>
        {loading && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 5, background: 'rgba(0,0,0,0.4)' }}>
            <span style={{ fontSize: 12, color: '#818cf8' }}>CFG oluşturuluyor...</span>
          </div>
        )}
        {error && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 5 }}>
            <span style={{ fontSize: 12, color: '#f87171' }}>Hata: {error}</span>
          </div>
        )}
        {nodes.length > 0 && (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            nodeTypes={cfgNodeTypes}
            fitView
            minZoom={0.1}
            maxZoom={2}
            proOptions={proOptions}
            style={{ background: 'transparent' }}
          >
            <Background variant="dots" gap={20} size={0.5} color="rgba(255,255,255,0.04)" />
            <Controls showInteractive={false} style={{ background: 'rgba(0,0,0,0.5)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)' }} />
            <MiniMap
              nodeColor={n => {
                const c = CFG_BLOCK_COLORS[n.data?.block_type];
                return c ? c.border : '#374151';
              }}
              maskColor="rgba(0,0,0,0.7)"
              style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}
            />
          </ReactFlow>
        )}
        {!loading && !error && nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, color: '#374151' }}>Fonksiyon seçin → CFG görüntüleyin</span>
          </div>
        )}
      </div>

      {/* Legend */}
      <div style={{
        padding: '4px 12px', borderTop: '1px solid rgba(255,255,255,0.04)',
        display: 'flex', gap: 12, flexWrap: 'wrap', flexShrink: 0,
      }}>
        {[
          { label: 'Entry', color: '#6366f1' },
          { label: 'Exit/RET', color: '#f87171' },
          { label: 'Branch', color: '#fbbf24' },
          { label: 'Call', color: '#60a5fa' },
          { label: 'Normal', color: '#374151' },
        ].map(l => (
          <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: '#64748b' }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: l.color }} />
            {l.label}
          </div>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <span style={{ fontSize: 9, color: '#22c55e' }}>── T (taken)</span>
          <span style={{ fontSize: 9, color: '#ef4444' }}>── F (fall)</span>
          <span style={{ fontSize: 9, color: '#f59e0b' }}>── JMP</span>
        </div>
      </div>
    </div>
  );
}

// ── DisassemblyPage (1.1 + 1.2) ─────────────────────────────────────────────

function DisassemblyPage({ filePath, onSendToChat }) {
  const [instructions, setInstructions] = useState([]);
  const [functions, setFunctions]       = useState([]);
  const [funcsLoading, setFuncsLoading] = useState(false);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState(null);
  const [is64, setIs64]                 = useState(true);
  const [currentAddr, setCurrentAddr]   = useState(0);
  const [gotoInput, setGotoInput]       = useState('');
  const [funcFilter, setFuncFilter]     = useState('');
  const [funcPanelOpen, setFuncPanelOpen] = useState(true);
  const [selectedFunc, setSelectedFunc] = useState(null);
  const [chunkSize]                     = useState(200);
  const [localFilePath, setLocalFilePath] = useState(filePath || null);
  const [cfgOpen, setCfgOpen]           = useState(false);
  const [cfgFuncAddr, setCfgFuncAddr]   = useState(null);
  const [cfgFuncName, setCfgFuncName]   = useState('');
  const [xrefOpen, setXrefOpen]         = useState(false);
  const [xrefAddr, setXrefAddr]         = useState(null);
  const [xrefData, setXrefData]         = useState(null);
  const [xrefLoading, setXrefLoading]   = useState(false);
  const [ctxMenu, setCtxMenu]           = useState(null); // {x,y,ins} for right-click
  const [patchLog, setPatchLog]         = useState([]);
  const listRef = useRef(null);
  const dragRef = useRef(null);

  const kindColor = {
    call: '#60a5fa', jmp: '#f59e0b', jcc: '#fbbf24', ret: '#f87171',
    nop: '#374151', data: '#94a3b8', cmp: '#c084fc', '': '#e2e8f0',
  };

  const loadChunk = useCallback(async (addr, isVirtual = true, count) => {
    if (!localFilePath) return;
    setLoading(true);
    setError(null);
    try {
      const r = await invoke('disassemble_at', {
        filePath: localFilePath,
        offset: addr,
        count: count || chunkSize,
        isVirtual,
      });
      setInstructions(r.instructions);
      setIs64(r.is_64);
      setCurrentAddr(r.start_addr);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [localFilePath, chunkSize]);

  const loadFunctions = useCallback(async () => {
    if (!localFilePath) return;
    setFuncsLoading(true);
    try {
      const r = await invoke('list_functions', { filePath: localFilePath });
      setFunctions(r);
      const ep = r.find(f => f.is_entry);
      if (ep) {
        loadChunk(ep.addr_val, true);
        setSelectedFunc(ep.addr_val);
      }
    } catch (e) {
      console.error('list_functions error:', e);
    } finally {
      setFuncsLoading(false);
    }
  }, [localFilePath, loadChunk]);

  useEffect(() => { if (filePath) setLocalFilePath(filePath); }, [filePath]);
  useEffect(() => { if (localFilePath) loadFunctions(); }, [localFilePath]);

  const handleDrop = async (e) => {
    e.preventDefault();
    const files = e.dataTransfer?.files;
    if (files?.length > 0 && files[0].path) setLocalFilePath(files[0].path);
  };

  const gotoAddress = () => {
    const input = gotoInput.trim();
    if (!input) return;
    const val = parseInt(input, 16) || parseInt(input, 10);
    if (!isNaN(val) && val >= 0) {
      loadChunk(val, input.toLowerCase().startsWith('0x') || val > 0x10000);
      setGotoInput('');
    }
  };

  const loadMore = () => {
    if (!instructions.length) return;
    const last = instructions[instructions.length - 1];
    loadChunk(last.addr_val + last.size, true);
  };

  const loadPrev = () => {
    if (!instructions.length || currentAddr === 0) return;
    loadChunk(Math.max(0, currentAddr - chunkSize * 4), true);
  };

  const jumpToTarget = (addr) => { loadChunk(addr, true); setSelectedFunc(null); };
  const goToFunc = (func) => {
    setSelectedFunc(func.addr_val);
    loadChunk(func.addr_val, true);
    setCfgFuncAddr(func.addr_val);
    setCfgFuncName(func.name);
  };

  const openCfgForFunc = (func) => {
    setCfgFuncAddr(func.addr_val);
    setCfgFuncName(func.name);
    setCfgOpen(true);
  };

  const onCfgBlockClick = (addr) => {
    loadChunk(addr, true);
  };

  // XRef functions
  const openXref = async (addr) => {
    if (!localFilePath || !addr) return;
    setXrefAddr(addr);
    setXrefOpen(true);
    setXrefLoading(true);
    try {
      const r = await invoke('get_xrefs', { filePath: localFilePath, targetAddr: addr });
      setXrefData(r);
    } catch (e) {
      setXrefData(null);
      console.error('XRef error:', e);
    } finally {
      setXrefLoading(false);
    }
  };

  // 2.6 — Decompile: send function assembly to AI chat
  const decompileFunc = (func) => {
    if (!instructions.length) return;
    // Get assembly text for the currently visible instructions (or a selected function's range)
    const asmLines = instructions.map(ins =>
      `${ins.addr}  ${ins.bytes?.padEnd(24) || ''}  ${ins.mnemonic} ${ins.operands}`
    ).join('\n');
    onSendToChat({
      type: 'disasm_func',
      fileName: localFilePath?.split(/[/\\]/).pop() || '?',
      funcName: func?.name || cfgFuncName || `func_${currentAddr.toString(16)}`,
      funcAddr: func?.addr || `0x${currentAddr.toString(16).toUpperCase()}`,
      arch: is64 ? 'x86-64' : 'x86',
      assembly: asmLines,
    });
  };

  // Patch functions
  const doPatch = async (addr, patchType) => {
    if (!localFilePath) return;
    setCtxMenu(null);
    try {
      const r = await invoke('patch_instruction', { filePath: localFilePath, addr, patchType });
      setPatchLog(prev => [r, ...prev].slice(0, 50));
      // Reload current view to show updated bytes
      if (currentAddr > 0) loadChunk(currentAddr, true);
    } catch (e) {
      alert('Patch hatası: ' + e);
    }
  };

  // Right-click handler
  const handleInsRightClick = (e, ins) => {
    e.preventDefault();
    setCtxMenu({ x: e.clientX, y: e.clientY, ins });
  };

  const filteredFuncs = funcFilter
    ? functions.filter(f => f.name.toLowerCase().includes(funcFilter.toLowerCase()) || f.addr.toLowerCase().includes(funcFilter.toLowerCase()))
    : functions;

  if (!localFilePath) {
    return (
      <div onDragOver={e => e.preventDefault()} onDrop={handleDrop}
        style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 40, gap: 16 }}>
        <Code size={48} color="#374151" />
        <div style={{ fontSize: 16, fontWeight: 600, color: '#e2e8f0' }}>Disassembly Görünümü</div>
        <div style={{ fontSize: 12, color: '#64748b', textAlign: 'center', maxWidth: 400 }}>
          PE dosyasını sürükleyip bırakın veya Scanner'dan "Tam Disassembly Görünümü" butonuna tıklayın.
        </div>
        <div style={{ fontSize: 11, color: '#374151', marginTop: 12, padding: '8px 16px', borderRadius: 8, border: '1px dashed rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.03)' }}>
          x86/x64 · Fonksiyon Listesi · Adres Navigasyonu · Branch Takibi
        </div>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }} onDragOver={e => e.preventDefault()} onDrop={handleDrop}>
      {/* Top bar */}
      <div style={{ padding: '8px 16px', background: 'rgba(0,0,0,0.2)', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <Code size={14} color="#818cf8" />
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>Disassembly</span>
        <span style={{ fontSize: 10, color: '#64748b' }}>{is64 ? 'x86-64' : 'x86'}</span>
        <span style={{ fontSize: 10, color: '#374151' }}>·</span>
        <span style={{ fontSize: 10, color: '#64748b', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{localFilePath.split(/[/\\]/).pop()}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          <input value={gotoInput} onChange={e => setGotoInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && gotoAddress()} placeholder="0x00401000 veya offset"
            style={{ width: 180, padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(0,0,0,0.3)', fontSize: 11, color: '#e2e8f0', fontFamily: 'monospace', outline: 'none' }} />
          <button onClick={gotoAddress} style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', fontSize: 11, cursor: 'pointer' }}>Git</button>
          <button onClick={() => setFuncPanelOpen(v => !v)}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: funcPanelOpen ? 'rgba(99,102,241,0.12)' : 'transparent', color: funcPanelOpen ? '#818cf8' : '#64748b', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
            <List size={12} /> Fonksiyonlar {functions.length > 0 && `(${functions.length})`}
          </button>
          <button onClick={() => { if (cfgFuncAddr) setCfgOpen(v => !v); }}
            disabled={!cfgFuncAddr}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: cfgOpen ? 'rgba(34,197,94,0.12)' : 'transparent', color: cfgOpen ? '#22c55e' : cfgFuncAddr ? '#64748b' : '#1f2937', fontSize: 11, cursor: cfgFuncAddr ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4 }}>
            <GitBranch size={12} /> CFG
          </button>
          {/* 2.6 — Decompile button */}
          <button onClick={() => decompileFunc(functions.find(f => f.addr_val === selectedFunc))}
            disabled={!instructions.length}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(139,92,246,0.2)', background: 'rgba(139,92,246,0.06)', color: instructions.length ? '#a78bfa' : '#1f2937', fontSize: 11, cursor: instructions.length ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Bot size={12} /> Decompile
          </button>
        </div>
      </div>

      {/* Main content */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Function panel */}
        {funcPanelOpen && (
          <div style={{ width: 260, flexShrink: 0, borderRight: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.15)' }}>
            <div style={{ padding: '8px 10px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <input value={funcFilter} onChange={e => setFuncFilter(e.target.value)} placeholder="Fonksiyon ara..."
                style={{ width: '100%', padding: '5px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', fontSize: 11, color: '#e2e8f0', outline: 'none' }} />
            </div>
            <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }}>
              {funcsLoading && <div style={{ padding: 20, textAlign: 'center', fontSize: 11, color: '#64748b' }}>Fonksiyonlar taranıyor...</div>}
              {!funcsLoading && filteredFuncs.map((f, i) => (
                <button key={i} onClick={() => goToFunc(f)}
                  style={{ width: '100%', border: 'none', cursor: 'pointer', padding: '6px 10px', textAlign: 'left',
                    background: selectedFunc === f.addr_val ? 'rgba(99,102,241,0.12)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                    borderLeft: `2px solid ${f.is_entry ? '#f59e0b' : selectedFunc === f.addr_val ? '#6366f1' : 'transparent'}`,
                    display: 'flex', flexDirection: 'column', gap: 1, transition: 'background 0.1s' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: f.is_entry ? '#f59e0b' : '#e2e8f0', fontFamily: 'monospace', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flex: 1 }}>{f.name}</span>
                    {f.call_count > 0 && <span style={{ fontSize: 9, color: '#60a5fa', background: 'rgba(96,165,250,0.1)', padding: '1px 5px', borderRadius: 4, flexShrink: 0 }}>{f.call_count}x</span>}
                    <span onClick={(e) => { e.stopPropagation(); openCfgForFunc(f); }}
                      style={{ fontSize: 9, color: '#22c55e', background: 'rgba(34,197,94,0.08)', padding: '1px 4px', borderRadius: 3, flexShrink: 0, cursor: 'pointer' }}
                      title="CFG görüntüle">
                      <GitBranch size={9} />
                    </span>
                    <span onClick={(e) => { e.stopPropagation(); openXref(f.addr_val); }}
                      style={{ fontSize: 9, color: '#818cf8', background: 'rgba(99,102,241,0.08)', padding: '1px 4px', borderRadius: 3, flexShrink: 0, cursor: 'pointer' }}
                      title="XRef göster">
                      <Search size={9} />
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 8, fontSize: 9, color: '#4b5563' }}>
                    <span>{f.addr}</span>
                    <span>{f.size > 1024 ? `${(f.size / 1024).toFixed(1)}KB` : `${f.size}B`}</span>
                  </div>
                </button>
              ))}
              {!funcsLoading && filteredFuncs.length === 0 && (
                <div style={{ padding: 16, fontSize: 11, color: '#374151', textAlign: 'center' }}>{functions.length === 0 ? 'Henüz taranmadı' : 'Sonuç yok'}</div>
              )}
            </div>
          </div>
        )}

        {/* Disassembly listing + CFG */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Disassembly section */}
          <div style={{ flex: cfgOpen ? '0 0 45%' : 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderBottom: cfgOpen ? '2px solid rgba(99,102,241,0.2)' : undefined }}>
          <div style={{ display: 'flex', gap: 6, padding: '4px 12px', borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(0,0,0,0.1)', alignItems: 'center' }}>
            <button onClick={loadPrev} disabled={loading || !instructions.length}
              style={{ padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
              <ArrowUp size={10} /> Yukarı
            </button>
            <button onClick={loadMore} disabled={loading || !instructions.length}
              style={{ padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
              <ArrowDown size={10} /> Aşağı
            </button>
            {currentAddr > 0 && <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace' }}>0x{currentAddr.toString(16).toUpperCase().padStart(8, '0')} — {instructions.length} talimat</span>}
            {loading && <span style={{ fontSize: 10, color: '#818cf8', marginLeft: 'auto' }}>Yükleniyor...</span>}
          </div>

          <div ref={listRef} style={{ flex: 1, overflowY: 'auto', overflowX: 'auto', fontFamily: '"JetBrains Mono", monospace' }}>
            {error && <div style={{ padding: 16, color: '#f87171', fontSize: 12 }}>Hata: {error}</div>}
            {!error && instructions.length === 0 && !loading && (
              <div style={{ padding: 32, textAlign: 'center', color: '#374151', fontSize: 12 }}>Sol panelden fonksiyon seçin veya adres girin</div>
            )}
            {instructions.length > 0 && (
              <div style={{ display: 'grid', gridTemplateColumns: '100px 60px 150px 75px 1fr', padding: '4px 12px', fontSize: 9, color: '#374151', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid rgba(255,255,255,0.06)', position: 'sticky', top: 0, background: 'rgba(13,17,23,0.97)', zIndex: 2 }}>
                <span>Adres</span><span>Offset</span><span>Bytes</span><span>Mnemonic</span><span>Operands</span>
              </div>
            )}
            {instructions.map((ins, i) => {
              const isBlockEnd = ins.kind === 'ret' || ins.kind === 'jmp';
              const isCall = ins.kind === 'call';
              const hasTarget = !!ins.target;
              return (
                <div key={i} style={{
                  display: 'grid', gridTemplateColumns: '100px 60px 150px 75px 1fr', padding: '2px 12px', fontSize: 11, lineHeight: '20px',
                  background: isBlockEnd ? 'rgba(248,113,113,0.03)' : isCall ? 'rgba(96,165,250,0.03)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.008)',
                  borderBottom: isBlockEnd ? '2px solid rgba(248,113,113,0.15)' : undefined,
                  cursor: hasTarget ? 'pointer' : 'default',
                }} onClick={() => hasTarget && jumpToTarget(ins.target_val)}
                   onContextMenu={(e) => handleInsRightClick(e, ins)}
                   onDoubleClick={() => openXref(ins.addr_val)}
                   title={hasTarget ? `Jump to ${ins.target} | Sağ tık: Patch | Çift tık: XRef` : 'Sağ tık: Patch | Çift tık: XRef'}>
                  <span style={{ color: '#4b5563', userSelect: 'text' }}>{ins.addr}</span>
                  <span style={{ color: '#1f2937', fontSize: 9, userSelect: 'text' }}>+{(ins.offset || 0).toString(16).toUpperCase()}</span>
                  <span style={{ color: '#374151', userSelect: 'text', fontSize: 10 }}>{ins.bytes}</span>
                  <span style={{ color: kindColor[ins.kind] || '#e2e8f0', fontWeight: 700, userSelect: 'text' }}>{ins.mnemonic}</span>
                  <span style={{ color: hasTarget ? '#818cf8' : '#94a3b8', userSelect: 'text', textDecoration: hasTarget ? 'underline' : 'none' }}>
                    {ins.operands}
                    {hasTarget && <span style={{ fontSize: 9, color: '#4b5563', marginLeft: 8 }}>→ {ins.target}</span>}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

          {/* CFG Panel */}
          {cfgOpen && cfgFuncAddr && localFilePath && (
            <CFGPanel
              filePath={localFilePath}
              funcAddr={cfgFuncAddr}
              funcName={cfgFuncName}
              onBlockClick={onCfgBlockClick}
              onClose={() => setCfgOpen(false)}
            />
          )}
        </div>
      </div>

      {/* Right-click context menu */}
      {ctxMenu && (
        <div onClick={() => setCtxMenu(null)} style={{ position: 'fixed', inset: 0, zIndex: 100 }}>
          <div style={{
            position: 'fixed', left: ctxMenu.x, top: ctxMenu.y,
            background: 'rgba(15,20,30,0.97)', border: '1px solid rgba(99,102,241,0.2)',
            borderRadius: 8, padding: 4, minWidth: 180, boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ padding: '4px 10px', fontSize: 10, color: '#4b5563', fontFamily: 'monospace', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              {ctxMenu.ins.addr} — {ctxMenu.ins.mnemonic} {ctxMenu.ins.operands}
            </div>
            {[
              { label: 'NOP ile değiştir', type: 'nop', color: '#64748b', icon: '90' },
              { label: 'JMP yap (zorla)', type: 'jmp', color: '#f59e0b', icon: 'EB' },
              { label: 'Koşulu ters çevir', type: 'invert', color: '#a78bfa', icon: '⊕' },
              { label: 'RET ile değiştir', type: 'ret', color: '#f87171', icon: 'C3' },
            ].map(p => (
              <button key={p.type} onClick={() => doPatch(ctxMenu.ins.addr_val, p.type)}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', border: 'none', background: 'transparent', color: '#e2e8f0', fontSize: 11, cursor: 'pointer', textAlign: 'left', borderRadius: 4 }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.1)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <span style={{ fontSize: 9, fontFamily: 'monospace', color: p.color, background: 'rgba(255,255,255,0.05)', padding: '1px 4px', borderRadius: 3, minWidth: 20, textAlign: 'center' }}>{p.icon}</span>
                {p.label}
              </button>
            ))}
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.04)', marginTop: 2 }}>
              <button onClick={() => { openXref(ctxMenu.ins.addr_val); setCtxMenu(null); }}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', border: 'none', background: 'transparent', color: '#818cf8', fontSize: 11, cursor: 'pointer', textAlign: 'left', borderRadius: 4 }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.1)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <Search size={10} /> XRef göster
              </button>
              {/* 2.6 — Decompile from context menu */}
              <button onClick={() => { decompileFunc(null); setCtxMenu(null); }}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', border: 'none', background: 'transparent', color: '#a78bfa', fontSize: 11, cursor: 'pointer', textAlign: 'left', borderRadius: 4 }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(139,92,246,0.1)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <Bot size={10} /> AI Decompile
              </button>
            </div>
          </div>
        </div>
      )}

      {/* XRef drawer */}
      {xrefOpen && (
        <div style={{
          position: 'absolute', right: 0, top: 0, bottom: 0, width: 340,
          background: 'rgba(10,14,22,0.98)', borderLeft: '1px solid rgba(99,102,241,0.15)',
          display: 'flex', flexDirection: 'column', zIndex: 50,
          boxShadow: '-4px 0 24px rgba(0,0,0,0.4)',
        }}>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <Search size={12} color="#818cf8" />
            <span style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0' }}>Cross-References</span>
            {xrefData && <span style={{ fontSize: 10, color: '#818cf8', fontFamily: 'monospace' }}>{xrefData.target_name}</span>}
            <button onClick={() => setXrefOpen(false)} style={{ marginLeft: 'auto', padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer' }}>
              <X size={10} />
            </button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
            {xrefLoading && <div style={{ padding: 20, textAlign: 'center', fontSize: 11, color: '#64748b' }}>Taranıyor...</div>}
            {xrefData && !xrefLoading && (
              <>
                {/* Refs TO this address */}
                <div style={{ fontSize: 10, fontWeight: 700, color: '#22c55e', padding: '6px 4px 4px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  Buraya referanslar ({xrefData.refs_to.length})
                </div>
                {xrefData.refs_to.length === 0 && <div style={{ padding: 8, fontSize: 10, color: '#374151' }}>Referans bulunamadı</div>}
                {xrefData.refs_to.map((r, i) => (
                  <button key={i} onClick={() => { loadChunk(r.from_addr_val, true); }}
                    style={{ display: 'flex', gap: 6, padding: '4px 6px', width: '100%', border: 'none', background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)', cursor: 'pointer', borderRadius: 3, textAlign: 'left', alignItems: 'center' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.08)'}
                    onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'}>
                    <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace', minWidth: 80 }}>{r.from_addr}</span>
                    <span style={{ fontSize: 10, fontWeight: 700, fontFamily: 'monospace', color: r.xref_type === 'call' ? '#60a5fa' : r.xref_type === 'data' ? '#94a3b8' : '#fbbf24', minWidth: 30 }}>{r.mnemonic}</span>
                    <span style={{ fontSize: 9, color: '#64748b' }}>[{r.context}]</span>
                  </button>
                ))}

                {/* Refs FROM this address */}
                <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', padding: '10px 4px 4px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  Buradan referanslar ({xrefData.refs_from.length})
                </div>
                {xrefData.refs_from.length === 0 && <div style={{ padding: 8, fontSize: 10, color: '#374151' }}>Referans bulunamadı</div>}
                {xrefData.refs_from.map((r, i) => (
                  <button key={i} onClick={() => { loadChunk(r.to_addr_val, true); }}
                    style={{ display: 'flex', gap: 6, padding: '4px 6px', width: '100%', border: 'none', background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)', cursor: 'pointer', borderRadius: 3, textAlign: 'left', alignItems: 'center' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.08)'}
                    onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'}>
                    <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace', minWidth: 80 }}>{r.to_addr}</span>
                    <span style={{ fontSize: 10, fontWeight: 700, fontFamily: 'monospace', color: r.xref_type === 'call' ? '#60a5fa' : '#fbbf24', minWidth: 30 }}>{r.mnemonic}</span>
                    <span style={{ fontSize: 9, color: '#818cf8' }}>{r.context}</span>
                  </button>
                ))}
              </>
            )}
          </div>
        </div>
      )}

      {/* Patch log toast */}
      {patchLog.length > 0 && (
        <div style={{ position: 'absolute', bottom: 12, right: 12, zIndex: 60, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {patchLog.slice(0, 3).map((p, i) => (
            <div key={i} style={{
              background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.2)',
              borderRadius: 6, padding: '6px 12px', fontSize: 10, color: '#22c55e',
              display: 'flex', gap: 8, alignItems: 'center', animation: 'fadeIn 0.3s',
            }}>
              <CheckCircle2 size={12} />
              <span style={{ fontFamily: 'monospace' }}>{p.description}</span>
              <span style={{ color: '#4b5563', fontSize: 9 }}>+0x{p.offset.toString(16).toUpperCase()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 4.3 — Dashboard / İstatistik Sayfası
// ══════════════════════════════════════════════════════════════════════

function DashboardPage() {
  const [history] = useState(getHistory);
  const [searchQ, setSearchQ] = useState('');
  const [searchRegex, setSearchRegex] = useState(false);
  const [filterArch, setFilterArch] = useState('all');
  const [filterRisk, setFilterRisk] = useState('all');
  const [filterPacker, setFilterPacker] = useState('all');
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');
  const [projectName, setProjectName] = useState('');
  const [projects, setProjects] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_projects') || '[]'); } catch { return []; }
  });
  const [activeProject, setActiveProject] = useState(null);

  const saveProjects = (p) => { setProjects(p); localStorage.setItem('dissect_projects', JSON.stringify(p)); };

  // ── 4.4 Advanced search with filters ───────────────────────────
  const filtered = useMemo(() => {
    let items = activeProject
      ? history.filter(h => (activeProject.fileIds || []).includes(h.id))
      : history;

    if (searchQ) {
      if (searchRegex) {
        try {
          const rx = new RegExp(searchQ, 'i');
          items = items.filter(h => rx.test(h.fileName) || rx.test(h.result?.sha256 || '') || rx.test(h.result?.md5 || '') || (h.result?.strings || []).some(s => rx.test(s.text || s)));
        } catch { /* invalid regex */ }
      } else {
        const q = searchQ.toLowerCase();
        items = items.filter(h => h.fileName?.toLowerCase().includes(q) || String(h.riskScore).includes(q) || h.arch?.includes(q) || (h.result?.sha256 || '').includes(q) || (h.result?.md5 || '').includes(q) || (h.packers || []).some(p => p.toLowerCase().includes(q)));
      }
    }
    if (filterArch !== 'all') items = items.filter(h => h.arch === filterArch);
    if (filterRisk === 'high') items = items.filter(h => h.riskScore >= 60);
    else if (filterRisk === 'moderate') items = items.filter(h => h.riskScore >= 30 && h.riskScore < 60);
    else if (filterRisk === 'clean') items = items.filter(h => h.riskScore < 30);
    if (filterPacker !== 'all') items = items.filter(h => (h.packers || []).includes(filterPacker));
    if (filterDateFrom) items = items.filter(h => h.ts >= filterDateFrom);
    if (filterDateTo) items = items.filter(h => h.ts <= filterDateTo + 'T23:59:59');
    return items;
  }, [history, searchQ, searchRegex, filterArch, filterRisk, filterPacker, filterDateFrom, filterDateTo, activeProject]);

  // ── Stats ──────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const total = filtered.length;
    const riskH = filtered.filter(h => h.riskScore >= 60).length;
    const riskM = filtered.filter(h => h.riskScore >= 30 && h.riskScore < 60).length;
    const riskL = filtered.filter(h => h.riskScore < 30).length;
    const avgRisk = total ? Math.round(filtered.reduce((s,h) => s + (h.riskScore||0), 0) / total) : 0;
    const x64 = filtered.filter(h => h.arch === 'x64').length;
    const x86 = filtered.filter(h => h.arch === 'x86').length;

    // Packer dist
    const packerMap = {};
    filtered.forEach(h => (h.packers || []).forEach(p => { packerMap[p] = (packerMap[p] || 0) + 1; }));
    const topPackers = Object.entries(packerMap).sort((a,b) => b[1]-a[1]).slice(0, 8);

    // DLL frequency from imports
    const dllMap = {};
    filtered.forEach(h => (h.result?.imports || []).forEach(imp => {
      const dll = (imp.dll || '').toLowerCase();
      if (dll) dllMap[dll] = (dllMap[dll] || 0) + 1;
    }));
    const topDlls = Object.entries(dllMap).sort((a,b) => b[1]-a[1]).slice(0, 10);

    // Timeline: scans per day
    const dayMap = {};
    filtered.forEach(h => {
      const d = (h.ts || '').slice(0, 10);
      if (d) dayMap[d] = (dayMap[d] || 0) + 1;
    });
    const timeline = Object.entries(dayMap).sort((a,b) => a[0].localeCompare(b[0])).slice(-14); // last 14 days

    // Protection breakdown
    const protections = { Denuvo: 0, VMProtect: 0, Themida: 0, AntiDebug: 0, AntiVM: 0 };
    filtered.forEach(h => {
      if (h.denuvo || h.result?.denuvo) protections.Denuvo++;
      if (h.vmp || h.result?.vmp) protections.VMProtect++;
      if (h.result?.themida) protections.Themida++;
      if (h.antiDebug || h.result?.antiDebug) protections.AntiDebug++;
      if (h.result?.antiVM) protections.AntiVM++;
    });

    return { total, riskH, riskM, riskL, avgRisk, x64, x86, topPackers, topDlls, timeline, protections };
  }, [filtered]);

  // ── PDF Export (4.1) ───────────────────────────────────────────
  const exportPDF = () => {
    const w = window.open('', '_blank');
    const rows = filtered.map(h => `<tr>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:12px;font-family:monospace">${h.fileName || '?'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:center">${h.arch || '?'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:center;color:${h.riskScore>=60?'#dc2626':h.riskScore>=30?'#d97706':'#16a34a'};font-weight:700">${h.riskScore ?? '—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:11px">${(h.packers||[]).join(', ')||'—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:10px;font-family:monospace;color:#666">${(h.result?.sha256||'').slice(0,16)||'—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:10px;color:#888">${(h.ts||'').slice(0,10)}</td>
    </tr>`).join('');
    w.document.write(`<!DOCTYPE html><html><head><title>Dissect Report — ${new Date().toLocaleDateString('tr-TR')}</title>
    <style>body{font-family:Inter,Arial,sans-serif;margin:30px 40px;color:#111}h1{font-size:22px;margin-bottom:4px}h2{font-size:14px;color:#6366f1;margin-top:24px}
    table{border-collapse:collapse;width:100%;margin-top:8px}th{background:#f3f4f6;padding:8px 10px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;border-bottom:2px solid #e5e7eb}
    .stat{display:inline-block;text-align:center;padding:12px 20px;margin:4px;border-radius:8px;background:#f9fafb;border:1px solid #e5e7eb}
    .stat .n{font-size:24px;font-weight:800}.stat .l{font-size:10px;color:#6b7280;margin-top:2px}
    @media print{body{margin:15px 20px}}</style></head><body>
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
      <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;color:white;font-size:22px;font-weight:900">D</div>
      <div><h1 style="margin:0">Dissect — Analysis Report</h1>
      <div style="font-size:12px;color:#6b7280">${new Date().toLocaleDateString('tr-TR', {year:'numeric',month:'long',day:'numeric'})} · ${filtered.length} dosya · Avg Risk: ${stats.avgRisk}</div></div>
    </div>
    <div style="margin-bottom:20px">
      <div class="stat"><div class="n">${stats.total}</div><div class="l">Total Scans</div></div>
      <div class="stat"><div class="n" style="color:#dc2626">${stats.riskH}</div><div class="l">High Risk</div></div>
      <div class="stat"><div class="n" style="color:#d97706">${stats.riskM}</div><div class="l">Moderate</div></div>
      <div class="stat"><div class="n" style="color:#16a34a">${stats.riskL}</div><div class="l">Clean</div></div>
      <div class="stat"><div class="n">${stats.x64}</div><div class="l">x64</div></div>
      <div class="stat"><div class="n">${stats.x86}</div><div class="l">x86</div></div>
    </div>
    ${stats.topPackers.length ? `<h2>Packer Distribution</h2><table><tr>${stats.topPackers.map(([p,c]) => `<td style="padding:6px 12px;text-align:center"><div style="font-weight:700;font-size:16px">${c}</div><div style="font-size:10px;color:#6b7280">${p}</div></td>`).join('')}</tr></table>` : ''}
    ${stats.topDlls.length ? `<h2>Most Common DLLs</h2><table><tr>${stats.topDlls.map(([d,c]) => `<td style="padding:6px 12px;text-align:center"><div style="font-weight:700;font-size:14px">${c}</div><div style="font-size:10px;font-family:monospace;color:#6b7280">${d}</div></td>`).join('')}</tr></table>` : ''}
    <h2>Scan Details</h2>
    <table><thead><tr><th>File</th><th>Arch</th><th>Risk</th><th>Packers</th><th>SHA-256</th><th>Date</th></tr></thead><tbody>${rows}</tbody></table>
    <div style="margin-top:30px;padding-top:12px;border-top:1px solid #e5e7eb;font-size:10px;color:#9ca3af;text-align:center">Generated by Dissect v1.0 · ${new Date().toISOString()}</div>
    </body></html>`);
    w.document.close();
    setTimeout(() => w.print(), 500);
  };

  const StatCard = ({ value, label, color }) => (
    <div style={{ padding: '14px 18px', borderRadius: 10, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', textAlign: 'center', minWidth: 80 }}>
      <div style={{ fontSize: 24, fontWeight: 800, color: color || '#e5e7eb', fontFamily: 'monospace' }}>{value}</div>
      <div style={{ fontSize: 10, color: '#4b5563', marginTop: 2 }}>{label}</div>
    </div>
  );

  const BarH = ({ value, max, color, label }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
      <span style={{ fontSize: 10, color: '#94a3b8', minWidth: 80, textAlign: 'right', fontFamily: 'monospace' }}>{label}</span>
      <div style={{ flex: 1, height: 14, borderRadius: 4, background: 'rgba(255,255,255,0.04)', overflow: 'hidden' }}>
        <div style={{ width: `${max > 0 ? (value/max*100) : 0}%`, height: '100%', background: color || '#6366f1', borderRadius: 4, transition: 'width 0.6s' }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color: '#e5e7eb', minWidth: 24, fontFamily: 'monospace' }}>{value}</span>
    </div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 800, color: '#e5e7eb', margin: 0, letterSpacing: '-0.02em' }}>📊 Dashboard</h2>
          <div style={{ fontSize: 11, color: '#4b5563', marginTop: 2 }}>FAZ 4 — İstatistikler · Arama · Projeler · Raporlama</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={exportPDF} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>📄 PDF Report</button>
        </div>
      </div>

      {/* Stats cards row */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        <StatCard value={stats.total} label="Toplam Tarama" color="#818cf8" />
        <StatCard value={stats.riskH} label="High Risk" color="#f87171" />
        <StatCard value={stats.riskM} label="Moderate" color="#fbbf24" />
        <StatCard value={stats.riskL} label="Clean" color="#4ade80" />
        <StatCard value={stats.avgRisk} label="Avg Risk" color={stats.avgRisk >= 60 ? '#f87171' : stats.avgRisk >= 30 ? '#fbbf24' : '#4ade80'} />
        <StatCard value={stats.x64} label="x64" color="#60a5fa" />
        <StatCard value={stats.x86} label="x86" color="#a78bfa" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* Timeline chart */}
        <Card>
          <CardHeader>Tarama Zaman Çizelgesi (son 14 gün)</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {stats.timeline.length === 0 ? <div style={{ fontSize: 11, color: '#374151' }}>Yeterli veri yok</div> : (
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80 }}>
                {stats.timeline.map(([day, count], i) => {
                  const maxC = Math.max(...stats.timeline.map(t => t[1]));
                  return (
                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                      <span style={{ fontSize: 9, color: '#818cf8', fontWeight: 700 }}>{count}</span>
                      <div style={{ width: '100%', height: `${maxC > 0 ? count/maxC*60 : 0}px`, background: 'linear-gradient(to top, #6366f1, #818cf8)', borderRadius: '3px 3px 0 0', minHeight: 2 }} />
                      <span style={{ fontSize: 8, color: '#374151', whiteSpace: 'nowrap' }}>{day.slice(5)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </Card>

        {/* Protection breakdown */}
        <Card>
          <CardHeader>Koruma Tespiti Dağılımı</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {(() => {
              const maxP = Math.max(...Object.values(stats.protections), 1);
              const colors = { Denuvo: '#f87171', VMProtect: '#fb923c', Themida: '#fbbf24', AntiDebug: '#60a5fa', AntiVM: '#a78bfa' };
              return Object.entries(stats.protections).map(([k, v]) => <BarH key={k} label={k} value={v} max={maxP} color={colors[k]} />);
            })()}
          </div>
        </Card>

        {/* Top packers */}
        <Card>
          <CardHeader>Packer Dağılımı</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {stats.topPackers.length === 0 ? <div style={{ fontSize: 11, color: '#374151' }}>Packer tespit edilmemiş</div> : (() => {
              const maxP = Math.max(...stats.topPackers.map(p => p[1]), 1);
              return stats.topPackers.map(([packer, count]) => <BarH key={packer} label={packer} value={count} max={maxP} color="#f59e0b" />);
            })()}
          </div>
        </Card>

        {/* Top DLLs */}
        <Card>
          <CardHeader>En Sık Görülen DLL'ler</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {stats.topDlls.length === 0 ? <div style={{ fontSize: 11, color: '#374151' }}>Import verisi yok</div> : (() => {
              const maxD = Math.max(...stats.topDlls.map(d => d[1]), 1);
              return stats.topDlls.map(([dll, count]) => <BarH key={dll} label={dll} value={count} max={maxD} color="#60a5fa" />);
            })()}
          </div>
        </Card>
      </div>

      {/* ── 4.4 Advanced Search + Filters ──────────────────────────── */}
      <Card>
        <CardHeader>Gelişmiş Arama & Filtreler (FAZ 4.4)</CardHeader>
        <div style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <input value={searchQ} onChange={e => setSearchQ(e.target.value)} placeholder={searchRegex ? 'Regex pattern...' : 'Dosya adı, hash, packer...'} style={{ flex: 1, minWidth: 200, fontSize: 12, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
            <label style={{ fontSize: 10, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
              <input type="checkbox" checked={searchRegex} onChange={e => setSearchRegex(e.target.checked)} style={{ accentColor: '#6366f1' }} /> Regex
            </label>
            <select value={filterArch} onChange={e => setFilterArch(e.target.value)} style={{ fontSize: 11, padding: '5px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#e5e7eb' }}>
              <option value="all">Tüm Arch</option>
              <option value="x64">x64</option>
              <option value="x86">x86</option>
            </select>
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)} style={{ fontSize: 11, padding: '5px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#e5e7eb' }}>
              <option value="all">Tüm Risk</option>
              <option value="high">High (60+)</option>
              <option value="moderate">Moderate (30-59)</option>
              <option value="clean">Clean (&lt;30)</option>
            </select>
            {(() => {
              const allPackers = [...new Set(history.flatMap(h => h.packers || []))];
              return allPackers.length > 0 ? (
                <select value={filterPacker} onChange={e => setFilterPacker(e.target.value)} style={{ fontSize: 11, padding: '5px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#e5e7eb' }}>
                  <option value="all">Tüm Packer</option>
                  {allPackers.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              ) : null;
            })()}
            <input type="date" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)} style={{ fontSize: 10, padding: '4px 6px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#94a3b8' }} />
            <span style={{ fontSize: 10, color: '#374151' }}>—</span>
            <input type="date" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)} style={{ fontSize: 10, padding: '4px 6px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#94a3b8' }} />
          </div>

          <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 8 }}>{filtered.length} / {history.length} sonuç</div>

          {/* Results table */}
          <div style={{ maxHeight: 320, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase' }}>Dosya</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Arch</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Risk</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Packers</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>SHA-256</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Tarih</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((h, i) => (
                  <tr key={h.id || i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '5px 10px', color: '#e5e7eb', fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.fileName}</td>
                    <td style={{ padding: '5px 10px', textAlign: 'center', color: '#94a3b8' }}>{h.arch}</td>
                    <td style={{ padding: '5px 10px', textAlign: 'center', fontWeight: 700, color: h.riskScore >= 60 ? '#f87171' : h.riskScore >= 30 ? '#fbbf24' : '#4ade80' }}>{h.riskScore}</td>
                    <td style={{ padding: '5px 10px', color: '#94a3b8', fontSize: 10 }}>{(h.packers || []).join(', ') || '—'}</td>
                    <td style={{ padding: '5px 10px', color: '#4b5563', fontFamily: 'monospace', fontSize: 9 }}>{(h.result?.sha256 || '').slice(0, 16) || '—'}</td>
                    <td style={{ padding: '5px 10px', color: '#4b5563', fontSize: 10 }}>{(h.ts || '').slice(0, 10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Card>

      {/* ── 4.5 Workspace / Proje ──────────────────────────────────── */}
      <Card style={{ marginTop: 16 }}>
        <CardHeader>Workspace / Projeler (FAZ 4.5)</CardHeader>
        <div style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
            <input value={projectName} onChange={e => setProjectName(e.target.value)} placeholder="Yeni proje adı..." style={{ flex: 1, fontSize: 12, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
            <button onClick={() => {
              if (!projectName.trim()) return;
              const p = { id: Date.now(), name: projectName.trim(), fileIds: [], notes: '', created: new Date().toISOString() };
              saveProjects([p, ...projects]);
              setProjectName('');
            }} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontWeight: 600 }}>+ Oluştur</button>
            {activeProject && <button onClick={() => setActiveProject(null)} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>✕ Proje filtresi kaldır</button>}
          </div>

          {projects.length === 0 ? <div style={{ fontSize: 11, color: '#374141' }}>Henüz proje yok. Yukarıdan oluşturabilirsiniz.</div> : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {projects.map(p => (
                <div key={p.id} style={{ padding: '8px 14px', borderRadius: 8, background: activeProject?.id === p.id ? 'rgba(99,102,241,0.15)' : 'rgba(255,255,255,0.03)', border: `1px solid ${activeProject?.id === p.id ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }} onClick={() => setActiveProject(activeProject?.id === p.id ? null : p)}>
                  <span style={{ fontSize: 12, color: '#e5e7eb', fontWeight: 600 }}>{p.name}</span>
                  <span style={{ fontSize: 9, color: '#4b5563' }}>{(p.fileIds || []).length} dosya</span>
                  {/* Add scans to project */}
                  <button onClick={e => {
                    e.stopPropagation();
                    const ids = filtered.map(h => h.id);
                    const updated = projects.map(pp => pp.id === p.id ? { ...pp, fileIds: [...new Set([...(pp.fileIds || []), ...ids])] } : pp);
                    saveProjects(updated);
                  }} style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer' }} title="Filtrelenen sonuçları projeye ekle">+ekle</button>
                  <button onClick={e => {
                    e.stopPropagation();
                    if (activeProject?.id === p.id) setActiveProject(null);
                    saveProjects(projects.filter(pp => pp.id !== p.id));
                  }} style={{ fontSize: 9, padding: '2px 5px', borderRadius: 4, border: 'none', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>✕</button>
                </div>
              ))}
            </div>
          )}

          {/* Project export */}
          {activeProject && (
            <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
              <button onClick={() => {
                const blob = new Blob([JSON.stringify({ project: activeProject, scans: filtered }, null, 2)], { type: 'application/json' });
                const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
                a.download = `dissect_project_${activeProject.name.replace(/\s+/g, '_')}_${Date.now()}.json`;
                a.click(); URL.revokeObjectURL(a.href);
              }} style={{ fontSize: 10, padding: '5px 12px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: 'pointer' }}>📦 Export Project JSON</button>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// FAZ 6 — İleri Seviye Analiz Araçları
// ══════════════════════════════════════════════════════════════════════

// ── 6.1 Canlı Süreç Bağlanma (Process Attach) ────────────────────

const MOCK_PROCESSES = [
  { pid: 4, name: 'System', arch: 'x64', mem: '0.1 MB', user: 'NT AUTHORITY\\SYSTEM', parent: 0, modules: 1, threads: 180 },
  { pid: 632, name: 'csrss.exe', arch: 'x64', mem: '4.8 MB', user: 'NT AUTHORITY\\SYSTEM', parent: 536, modules: 12, threads: 14 },
  { pid: 1288, name: 'explorer.exe', arch: 'x64', mem: '92.3 MB', user: 'DESKTOP\\User', parent: 1200, modules: 215, threads: 47 },
  { pid: 2840, name: 'chrome.exe', arch: 'x64', mem: '214.5 MB', user: 'DESKTOP\\User', parent: 1288, modules: 78, threads: 32 },
  { pid: 3104, name: 'target_app.exe', arch: 'x86', mem: '18.7 MB', user: 'DESKTOP\\User', parent: 1288, modules: 24, threads: 8 },
  { pid: 3456, name: 'notepad.exe', arch: 'x64', mem: '5.2 MB', user: 'DESKTOP\\User', parent: 1288, modules: 16, threads: 3 },
  { pid: 4012, name: 'svchost.exe', arch: 'x64', mem: '32.1 MB', user: 'NT AUTHORITY\\LOCAL SERVICE', parent: 756, modules: 45, threads: 22 },
  { pid: 4200, name: 'malware_sample.exe', arch: 'x86', mem: '6.4 MB', user: 'DESKTOP\\User', parent: 1288, modules: 8, threads: 4 },
  { pid: 5120, name: 'cmd.exe', arch: 'x64', mem: '3.8 MB', user: 'DESKTOP\\User', parent: 1288, modules: 11, threads: 2 },
  { pid: 5544, name: 'powershell.exe', arch: 'x64', mem: '78.6 MB', user: 'DESKTOP\\User', parent: 5120, modules: 52, threads: 15 },
  { pid: 6200, name: 'packed_binary.exe', arch: 'x86', mem: '42.0 MB', user: 'DESKTOP\\User', parent: 1288, modules: 5, threads: 6 },
  { pid: 7700, name: 'vmtoolsd.exe', arch: 'x64', mem: '12.3 MB', user: 'NT AUTHORITY\\SYSTEM', parent: 756, modules: 28, threads: 9 },
];

const MOCK_MEMORY_REGIONS = [
  { base: '0x00400000', size: '0x1000', type: 'PE Header', protect: 'R--', state: 'Committed', info: 'IMAGE' },
  { base: '0x00401000', size: '0x5000', type: '.text', protect: 'R-X', state: 'Committed', info: 'IMAGE — Code section' },
  { base: '0x00406000', size: '0x2000', type: '.rdata', protect: 'R--', state: 'Committed', info: 'IMAGE — Read-only data' },
  { base: '0x00408000', size: '0x1000', type: '.data', protect: 'RW-', state: 'Committed', info: 'IMAGE — Initialized data' },
  { base: '0x00409000', size: '0x1000', type: '.rsrc', protect: 'R--', state: 'Committed', info: 'IMAGE — Resources' },
  { base: '0x0040A000', size: '0x1000', type: '.reloc', protect: 'R--', state: 'Committed', info: 'IMAGE — Relocations' },
  { base: '0x00500000', size: '0x10000', type: 'Heap', protect: 'RW-', state: 'Committed', info: 'Private heap' },
  { base: '0x00510000', size: '0x4000', type: 'Heap', protect: 'RW-', state: 'Committed', info: 'Growing heap block' },
  { base: '0x00700000', size: '0x1000', type: 'Stack', protect: 'RW-', state: 'Committed', info: 'Thread 0 stack' },
  { base: '0x10000000', size: '0xA000', type: 'DLL', protect: 'R-X', state: 'Committed', info: 'ntdll.dll .text' },
  { base: '0x7FFE0000', size: '0x1000', type: 'SharedData', protect: 'R--', state: 'Committed', info: 'KUSER_SHARED_DATA' },
  { base: '0x77000000', size: '0x19F000', type: 'DLL', protect: 'R-X', state: 'Committed', info: 'kernel32.dll' },
];

function ProcessAttachPage() {
  const [procs, setProcs] = useState(MOCK_PROCESSES);
  const [search, setSearch] = useState('');
  const [attached, setAttached] = useState(null);
  const [regions, setRegions] = useState([]);
  const [memDump, setMemDump] = useState(null);
  const [readAddr, setReadAddr] = useState('0x00401000');
  const [readSize, setReadSize] = useState('64');
  const [loading, setLoading] = useState(false);
  const [sortKey, setSortKey] = useState('pid');
  const [sortAsc, setSortAsc] = useState(true);

  const filtered = useMemo(() => {
    let list = procs.filter(p => p.name.toLowerCase().includes(search.toLowerCase()) || String(p.pid).includes(search));
    list.sort((a, b) => {
      const av = a[sortKey], bv = b[sortKey];
      const cmp = typeof av === 'string' ? av.localeCompare(bv) : av - bv;
      return sortAsc ? cmp : -cmp;
    });
    return list;
  }, [procs, search, sortKey, sortAsc]);

  const doAttach = (proc) => {
    setLoading(true);
    setTimeout(() => {
      setAttached(proc);
      setRegions(MOCK_MEMORY_REGIONS);
      setMemDump(null);
      setLoading(false);
    }, 600);
  };

  const doDetach = () => { setAttached(null); setRegions([]); setMemDump(null); };

  const doReadMem = () => {
    setLoading(true);
    setTimeout(() => {
      const bytes = Array.from({ length: parseInt(readSize) || 64 }, (_, i) => {
        const patterns = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57, 0x8D, 0x45, 0xF0, 0x50, 0xFF, 0x15, 0x00];
        return patterns[i % patterns.length] ^ ((i >> 4) & 0xFF);
      });
      setMemDump({ addr: readAddr, bytes });
      setLoading(false);
    }, 400);
  };

  const hexRow = (bytes, startAddr) => {
    const rows = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const addr = (parseInt(startAddr, 16) + i).toString(16).padStart(8, '0').toUpperCase();
      const hex = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      const ascii = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      rows.push({ addr, hex: hex.padEnd(48, ' '), ascii });
    }
    return rows;
  };

  const SortHeader = ({ label, k }) => (
    <th onClick={() => { if (sortKey === k) setSortAsc(!sortAsc); else { setSortKey(k); setSortAsc(true); } }}
      style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, color: sortKey === k ? '#818cf8' : '#8b949e', cursor: 'pointer', whiteSpace: 'nowrap', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
      {label} {sortKey === k ? (sortAsc ? '▲' : '▼') : ''}
    </th>
  );

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
        <Monitor size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Process Attach</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Canlı Süreç Bağlanma & Bellek Okuma</span>
        {attached && (
          <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e66', display: 'inline-block' }} />
            <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>Attached: {attached.name} (PID {attached.pid})</span>
            <button onClick={doDetach} style={{ marginLeft: 8, fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>Detach</button>
          </span>
        )}
      </div>

      {loading && <div style={{ textAlign: 'center', padding: 30, color: '#818cf8' }}><div style={{ width: 20, height: 20, border: '2px solid #818cf8', borderTopColor: 'transparent', borderRadius: '50%', animation: '_sp 0.6s linear infinite', display: 'inline-block' }} /></div>}

      {!attached && !loading && (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <Search size={13} color="#8b949e" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="PID veya isim ara..." style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            <button onClick={() => setProcs([...MOCK_PROCESSES])} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: 'pointer' }}><RefreshCw size={11} style={{ marginRight: 4 }} />Yenile</button>
          </div>
          <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead><tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                <SortHeader label="PID" k="pid" />
                <SortHeader label="Process Name" k="name" />
                <SortHeader label="Arch" k="arch" />
                <SortHeader label="Memory" k="mem" />
                <SortHeader label="Threads" k="threads" />
                <SortHeader label="User" k="user" />
                <th style={{ padding: '6px 10px', fontSize: 10, color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}></th>
              </tr></thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.pid} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', cursor: 'pointer' }}
                    onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                    onMouseOut={e => e.currentTarget.style.background = ''}>
                    <td style={{ padding: '5px 10px', color: '#818cf8', fontFamily: 'monospace' }}>{p.pid}</td>
                    <td style={{ padding: '5px 10px', fontWeight: 600, color: '#e6edf3' }}>{p.name}</td>
                    <td style={{ padding: '5px 10px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: p.arch === 'x86' ? 'rgba(245,158,11,0.12)' : 'rgba(99,102,241,0.12)', color: p.arch === 'x86' ? '#f59e0b' : '#818cf8' }}>{p.arch}</span></td>
                    <td style={{ padding: '5px 10px', fontFamily: 'monospace', color: '#8b949e' }}>{p.mem}</td>
                    <td style={{ padding: '5px 10px', fontFamily: 'monospace', color: '#8b949e' }}>{p.threads}</td>
                    <td style={{ padding: '5px 10px', color: '#8b949e', fontSize: 10 }}>{p.user}</td>
                    <td style={{ padding: '5px 10px' }}>
                      <button onClick={() => doAttach(p)} style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer' }}>Attach</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 8, fontSize: 10, color: '#8b949e' }}>Toplam: {filtered.length} süreç · ⚠ Gerçek attach için Windows API + Yönetici yetkisi gerekir</div>
        </Card>
      )}

      {attached && !loading && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <Card style={{ flex: 2, minWidth: 400 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📦 Bellek Bölgeleri — {attached.name}</div>
            <div style={{ overflowX: 'auto', maxHeight: 340, overflowY: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Base Address</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Size</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Type</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Protect</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>State</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Info</th>
                </tr></thead>
                <tbody>
                  {regions.map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                      onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                      onMouseOut={e => e.currentTarget.style.background = ''}>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8' }}>{r.base}</td>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3' }}>{r.size}</td>
                      <td style={{ padding: '4px 8px' }}>
                        <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4,
                          background: r.type === '.text' ? 'rgba(239,68,68,0.12)' : r.type === 'Heap' ? 'rgba(245,158,11,0.12)' : r.type === 'DLL' ? 'rgba(59,130,246,0.12)' : 'rgba(255,255,255,0.06)',
                          color: r.type === '.text' ? '#f87171' : r.type === 'Heap' ? '#f59e0b' : r.type === 'DLL' ? '#60a5fa' : '#8b949e'
                        }}>{r.type}</span>
                      </td>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', fontWeight: 600,
                        color: r.protect.includes('X') ? '#f87171' : r.protect.includes('W') ? '#f59e0b' : '#22c55e'
                      }}>{r.protect}</td>
                      <td style={{ padding: '4px 8px', color: '#8b949e' }}>{r.state}</td>
                      <td style={{ padding: '4px 8px', color: '#8b949e', fontSize: 9 }}>{r.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card style={{ flex: 1, minWidth: 300 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>🔍 Bellek Oku</div>
            <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 120 }}>
                <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Adres</div>
                <input value={readAddr} onChange={e => setReadAddr(e.target.value)} style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
              </div>
              <div style={{ width: 60 }}>
                <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Boyut</div>
                <input value={readSize} onChange={e => setReadSize(e.target.value)} style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button onClick={doReadMem} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>Oku</button>
              </div>
            </div>
            {memDump && (
              <div style={{ background: '#0d1117', borderRadius: 6, padding: 8, fontFamily: 'monospace', fontSize: 10, overflowX: 'auto', border: '1px solid rgba(255,255,255,0.06)', maxHeight: 260, overflowY: 'auto' }}>
                {hexRow(memDump.bytes, memDump.addr).map((r, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, lineHeight: '18px' }}>
                    <span style={{ color: '#818cf8', minWidth: 70 }}>{r.addr}</span>
                    <span style={{ color: '#e6edf3', minWidth: 340 }}>{r.hex}</span>
                    <span style={{ color: '#6e7681' }}>{r.ascii}</span>
                  </div>
                ))}
              </div>
            )}
            <div style={{ marginTop: 8, fontSize: 10, color: '#6e7681' }}>Hızlı bölge seçimi:</div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
              {regions.filter(r => r.type === '.text' || r.type === '.data' || r.type === 'Heap').map((r, i) => (
                <button key={i} onClick={() => { setReadAddr(r.base); setReadSize(String(parseInt(r.size, 16))); }}
                  style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#8b949e', cursor: 'pointer' }}>
                  {r.type} @ {r.base}
                </button>
              ))}
            </div>
          </Card>

          <Card style={{ width: '100%' }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📊 Süreç Detayları</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(175px, 1fr))', gap: 10 }}>
              {[
                { label: 'PID', value: attached.pid, color: '#818cf8' },
                { label: 'İsim', value: attached.name, color: '#e6edf3' },
                { label: 'Mimari', value: attached.arch, color: attached.arch === 'x86' ? '#f59e0b' : '#818cf8' },
                { label: 'Bellek', value: attached.mem, color: '#22c55e' },
                { label: 'Thread', value: attached.threads, color: '#60a5fa' },
                { label: 'Modüller', value: attached.modules, color: '#a78bfa' },
                { label: 'Parent PID', value: attached.parent, color: '#8b949e' },
                { label: 'Kullanıcı', value: attached.user, color: '#8b949e' },
              ].map((d, i) => (
                <div key={i} style={{ padding: '8px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 2 }}>{d.label}</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: d.color, fontFamily: typeof d.value === 'number' ? 'monospace' : 'inherit' }}>{d.value}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

// ── 6.2 Debugger Entegrasyonu ─────────────────────────────────────

const MOCK_REGISTERS = {
  x64: { RAX: '0x00000001400010A0', RBX: '0x0000000000000000', RCX: '0x000000014000D230', RDX: '0x0000000000000001', RSI: '0x0000000000000000', RDI: '0x00000001400045B0', RSP: '0x00000000006FF8B0', RBP: '0x00000000006FF8E0', R8: '0x0000000000000040', R9: '0x0000000000000000', R10: '0x00007FFE74CB0000', R11: '0x00000000006FF848', R12: '0x0000000000000000', R13: '0x0000000000000000', R14: '0x00000001400045B0', R15: '0x0000000000000000', RIP: '0x00000001400012C4', RFLAGS: '0x0000000000000246' },
  x86: { EAX: '0x004010A0', EBX: '0x00000000', ECX: '0x0040D230', EDX: '0x00000001', ESI: '0x00000000', EDI: '0x004045B0', ESP: '0x0019FF80', EBP: '0x0019FF88', EIP: '0x004012C4', EFLAGS: '0x00000246' },
};

const MOCK_DEBUG_DISASM = [
  { addr: '0x004012C0', bytes: '55', inst: 'push ebp', label: 'sub_4012C0' },
  { addr: '0x004012C1', bytes: '8BEC', inst: 'mov ebp, esp' },
  { addr: '0x004012C3', bytes: '83EC10', inst: 'sub esp, 0x10' },
  { addr: '0x004012C6', bytes: '53', inst: 'push ebx' },
  { addr: '0x004012C7', bytes: '56', inst: 'push esi' },
  { addr: '0x004012C8', bytes: '57', inst: 'push edi' },
  { addr: '0x004012C9', bytes: '8D45F0', inst: 'lea eax, [ebp-0x10]' },
  { addr: '0x004012CC', bytes: '50', inst: 'push eax' },
  { addr: '0x004012CD', bytes: 'FF1500304000', inst: 'call dword [0x403000]', comment: '; GetModuleHandleA' },
  { addr: '0x004012D3', bytes: '8945FC', inst: 'mov [ebp-4], eax' },
  { addr: '0x004012D6', bytes: '837DFC00', inst: 'cmp dword [ebp-4], 0' },
  { addr: '0x004012DA', bytes: '7520', inst: 'jnz 0x4012FC' },
  { addr: '0x004012DC', bytes: '6A00', inst: 'push 0' },
  { addr: '0x004012DE', bytes: '6804504000', inst: 'push 0x405004', comment: '; "Error"' },
  { addr: '0x004012E3', bytes: '6810504000', inst: 'push 0x405010', comment: '; "Module not found"' },
  { addr: '0x004012E8', bytes: '6A00', inst: 'push 0' },
  { addr: '0x004012EA', bytes: 'FF1504304000', inst: 'call dword [0x403004]', comment: '; MessageBoxA' },
  { addr: '0x004012F0', bytes: '33C0', inst: 'xor eax, eax' },
  { addr: '0x004012F2', bytes: '5F', inst: 'pop edi' },
  { addr: '0x004012F3', bytes: '5E', inst: 'pop esi' },
  { addr: '0x004012F4', bytes: '5D', inst: 'pop ebp' },
  { addr: '0x004012F5', bytes: 'C3', inst: 'ret' },
];

const MOCK_STACK = [
  { addr: '0x0019FF80', value: '0x0019FF88', info: 'saved EBP' },
  { addr: '0x0019FF84', value: '0x004013A2', info: 'return address → main+0x12' },
  { addr: '0x0019FF88', value: '0x0019FFD0', info: 'caller EBP' },
  { addr: '0x0019FF8C', value: '0x00000001', info: 'argc' },
  { addr: '0x0019FF90', value: '0x00532480', info: 'argv' },
  { addr: '0x0019FF94', value: '0x00532540', info: 'envp' },
  { addr: '0x0019FF98', value: '0x00000000', info: '(padding)' },
  { addr: '0x0019FF9C', value: '0x7FFE0300', info: 'KUSER_SHARED_DATA' },
];

function DebuggerPage() {
  const [arch, setArch] = useState('x86');
  const [regs, setRegs] = useState({ ...MOCK_REGISTERS.x86 });
  const [bps, setBps] = useState([{ addr: '0x004012CD', enabled: true, hits: 3 }, { addr: '0x004012DA', enabled: true, hits: 1 }]);
  const [newBp, setNewBp] = useState('');
  const [pc, setPc] = useState('0x004012C4');
  const [running, setRunning] = useState(false);
  const [stepMode, setStepMode] = useState(null);
  const [dbgLog, setDbgLog] = useState(['[Debugger] Target loaded: target_app.exe (x86)', '[Debugger] Breakpoint 0x004012CD set (GetModuleHandleA call)', '[Debugger] Breakpoint 0x004012DA set (conditional jump)', '[Debugger] Ready — press Step/Run']);

  const addBp = () => {
    if (!newBp.match(/^0x[0-9a-fA-F]+$/)) return;
    setBps(prev => [...prev, { addr: newBp, enabled: true, hits: 0 }]);
    setDbgLog(prev => [...prev, `[Debugger] Breakpoint at ${newBp} set`]);
    setNewBp('');
  };

  const doStep = () => {
    setStepMode('step');
    const curIdx = MOCK_DEBUG_DISASM.findIndex(d => d.addr === pc);
    if (curIdx >= 0 && curIdx < MOCK_DEBUG_DISASM.length - 1) {
      const next = MOCK_DEBUG_DISASM[curIdx + 1];
      setPc(next.addr);
      const regKey = arch === 'x64' ? 'RIP' : 'EIP';
      setRegs(prev => ({ ...prev, [regKey]: next.addr.replace('0x00', '0x00000001') }));
      setDbgLog(prev => [...prev, `[Step] ${next.addr}: ${next.inst}`]);
      const bp = bps.find(b => b.addr === next.addr && b.enabled);
      if (bp) {
        bp.hits++;
        setBps([...bps]);
        setDbgLog(prev => [...prev, `[Break] Hit breakpoint at ${next.addr} (${bp.hits}x)`]);
      }
    }
  };

  const doRun = () => {
    setRunning(true);
    setDbgLog(prev => [...prev, '[Run] Executing...']);
    setTimeout(() => {
      const bpAddrs = bps.filter(b => b.enabled).map(b => b.addr);
      const curIdx = MOCK_DEBUG_DISASM.findIndex(d => d.addr === pc);
      let hitIdx = -1;
      for (let i = curIdx + 1; i < MOCK_DEBUG_DISASM.length; i++) {
        if (bpAddrs.includes(MOCK_DEBUG_DISASM[i].addr)) { hitIdx = i; break; }
      }
      if (hitIdx >= 0) {
        const hit = MOCK_DEBUG_DISASM[hitIdx];
        setPc(hit.addr);
        const bp = bps.find(b => b.addr === hit.addr);
        if (bp) { bp.hits++; setBps([...bps]); }
        setDbgLog(prev => [...prev, `[Break] Hit breakpoint at ${hit.addr} — ${hit.inst}`]);
      } else {
        setDbgLog(prev => [...prev, '[Run] Reached end of function']);
      }
      setRunning(false);
    }, 500);
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Terminal size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Debugger</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Step · Breakpoint · Register</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          {['x86', 'x64'].map(a => (
            <button key={a} onClick={() => { setArch(a); setRegs({ ...MOCK_REGISTERS[a] }); }}
              style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: `1px solid ${arch === a ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: arch === a ? 'rgba(99,102,241,0.12)' : 'transparent', color: arch === a ? '#818cf8' : '#8b949e', cursor: 'pointer' }}>{a}</button>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 14 }}>
        <button onClick={doStep} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: running ? 'not-allowed' : 'pointer', opacity: running ? 0.5 : 1, fontWeight: 600 }}>⏭ Step Into</button>
        <button onClick={doStep} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: running ? 'not-allowed' : 'pointer', opacity: running ? 0.5 : 1 }}>⏩ Step Over</button>
        <button onClick={doRun} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.12)', color: '#22c55e', cursor: running ? 'not-allowed' : 'pointer', opacity: running ? 0.5 : 1, fontWeight: 600 }}>▶ Run</button>
        <button onClick={() => { setPc('0x004012C0'); setRegs({ ...MOCK_REGISTERS[arch] }); setDbgLog(prev => [...prev, '[Debugger] Reset to entry']); }}
          style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer' }}>↺ Restart</button>
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {/* Disassembly */}
        <Card style={{ flex: 2, minWidth: 380 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Disassembly</div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, maxHeight: 380, overflowY: 'auto', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
            {MOCK_DEBUG_DISASM.map((d, i) => {
              const isCur = d.addr === pc;
              const isBp = bps.some(b => b.addr === d.addr && b.enabled);
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 8px', background: isCur ? 'rgba(99,102,241,0.15)' : isBp ? 'rgba(239,68,68,0.06)' : 'transparent', borderLeft: isCur ? '3px solid #818cf8' : isBp ? '3px solid #f87171' : '3px solid transparent' }}>
                  <span style={{ color: isBp ? '#f87171' : 'transparent', fontSize: 8, minWidth: 10, cursor: 'pointer' }}
                    onClick={() => { if (isBp) setBps(bps.filter(b => b.addr !== d.addr)); else setBps([...bps, { addr: d.addr, enabled: true, hits: 0 }]); }}>
                    {isBp ? '●' : '○'}
                  </span>
                  {d.label && <span style={{ color: '#a78bfa', fontSize: 9, position: 'absolute', marginTop: -14 }}>{d.label}:</span>}
                  <span style={{ color: '#818cf8', minWidth: 80 }}>{d.addr}</span>
                  <span style={{ color: '#6e7681', minWidth: 90, fontSize: 10 }}>{d.bytes}</span>
                  <span style={{ color: isCur ? '#e6edf3' : '#c9d1d9', fontWeight: isCur ? 700 : 400 }}>{d.inst}</span>
                  {d.comment && <span style={{ color: '#22c55e', marginLeft: 8, fontSize: 10 }}>{d.comment}</span>}
                </div>
              );
            })}
          </div>
        </Card>

        {/* Registers + Stack */}
        <div style={{ flex: 1, minWidth: 220, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Registers ({arch})</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 200, overflowY: 'auto' }}>
              {Object.entries(regs).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '1px 4px', borderRadius: 3, background: (k === 'RIP' || k === 'EIP') ? 'rgba(99,102,241,0.1)' : 'transparent' }}>
                  <span style={{ color: (k === 'RIP' || k === 'EIP') ? '#818cf8' : (k.includes('FLAGS') ? '#f59e0b' : '#8b949e'), fontWeight: 600, minWidth: 52 }}>{k}</span>
                  <span style={{ color: '#e6edf3' }}>{v}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Breakpoints</div>
            <div style={{ display: 'flex', gap: 4, marginBottom: 6 }}>
              <input value={newBp} onChange={e => setNewBp(e.target.value)} placeholder="0x..." onKeyDown={e => e.key === 'Enter' && addBp()}
                style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
              <button onClick={addBp} style={{ fontSize: 9, padding: '3px 8px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>+ BP</button>
            </div>
            {bps.map((b, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, padding: '2px 0' }}>
                <span style={{ cursor: 'pointer', color: b.enabled ? '#f87171' : '#6e7681' }}
                  onClick={() => { b.enabled = !b.enabled; setBps([...bps]); }}>{b.enabled ? '●' : '○'}</span>
                <span style={{ fontFamily: 'monospace', color: '#e6edf3' }}>{b.addr}</span>
                <span style={{ color: '#6e7681', fontSize: 9 }}>({b.hits}x hit)</span>
                <span style={{ marginLeft: 'auto', cursor: 'pointer', color: '#6e7681', fontSize: 10 }}
                  onClick={() => setBps(bps.filter((_, j) => j !== i))}>✕</span>
              </div>
            ))}
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Call Stack</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10 }}>
              {MOCK_STACK.map((s, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: '1px 0' }}>
                  <span style={{ color: '#818cf8', minWidth: 80 }}>{s.addr}</span>
                  <span style={{ color: '#e6edf3', minWidth: 80 }}>{s.value}</span>
                  <span style={{ color: '#6e7681', fontSize: 9 }}>{s.info}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      {/* Debug Log */}
      <Card style={{ marginTop: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Debug Log</div>
        <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 120, overflowY: 'auto', background: '#0d1117', borderRadius: 6, padding: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
          {dbgLog.map((l, i) => (
            <div key={i} style={{ color: l.includes('[Break]') ? '#f87171' : l.includes('[Step]') ? '#818cf8' : l.includes('[Run]') ? '#22c55e' : '#8b949e', lineHeight: '16px' }}>{l}</div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── 6.3 Emülasyon Motoru ──────────────────────────────────────────

function EmulationPage() {
  const [code, setCode] = useState(MOCK_DEBUG_DISASM.slice(0, 12).map(d => `${d.addr}  ${d.inst}`).join('\n'));
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState(-1);
  const [emuRegs, setEmuRegs] = useState(null);
  const [history, setHistory] = useState([]);
  const [memWrites, setMemWrites] = useState([]);
  const [speed, setSpeed] = useState(200);

  const EMU_STEPS = [
    { inst: 'push ebp', regs: { EAX: 0, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF7C, EBP: 0x0019FF80, EIP: 0x004012C1 }, mem: [] },
    { inst: 'mov ebp, esp', regs: { EAX: 0, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF7C, EBP: 0x0019FF7C, EIP: 0x004012C3 }, mem: [] },
    { inst: 'sub esp, 0x10', regs: { EAX: 0, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF6C, EBP: 0x0019FF7C, EIP: 0x004012C6 }, mem: [] },
    { inst: 'push ebx', regs: { EAX: 0, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF68, EBP: 0x0019FF7C, EIP: 0x004012C7 }, mem: [{ addr: '0x0019FF68', val: '0x00000000', note: 'EBX saved' }] },
    { inst: 'push esi', regs: { EAX: 0, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF64, EBP: 0x0019FF7C, EIP: 0x004012C8 }, mem: [{ addr: '0x0019FF64', val: '0x00000000', note: 'ESI saved' }] },
    { inst: 'push edi', regs: { EAX: 0, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF60, EBP: 0x0019FF7C, EIP: 0x004012C9 }, mem: [{ addr: '0x0019FF60', val: '0x00000000', note: 'EDI saved' }] },
    { inst: 'lea eax, [ebp-0x10]', regs: { EAX: 0x0019FF6C, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF60, EBP: 0x0019FF7C, EIP: 0x004012CC }, mem: [] },
    { inst: 'push eax', regs: { EAX: 0x0019FF6C, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF5C, EBP: 0x0019FF7C, EIP: 0x004012CD }, mem: [{ addr: '0x0019FF5C', val: '0x0019FF6C', note: 'arg for GetModuleHandle' }] },
    { inst: 'call GetModuleHandleA', regs: { EAX: 0x00400000, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF60, EBP: 0x0019FF7C, EIP: 0x004012D3 }, mem: [] },
    { inst: 'mov [ebp-4], eax', regs: { EAX: 0x00400000, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF60, EBP: 0x0019FF7C, EIP: 0x004012D6 }, mem: [{ addr: '0x0019FF78', val: '0x00400000', note: 'hModule stored' }] },
    { inst: 'cmp [ebp-4], 0', regs: { EAX: 0x00400000, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF60, EBP: 0x0019FF7C, EIP: 0x004012DA, EFLAGS: 'ZF=0 CF=0' }, mem: [] },
    { inst: 'jnz 0x4012FC', regs: { EAX: 0x00400000, EBX: 0, ECX: 0, EDX: 0, ESI: 0, EDI: 0, ESP: 0x0019FF60, EBP: 0x0019FF7C, EIP: 0x004012FC }, mem: [] },
  ];

  const doRun = () => {
    setRunning(true);
    setStep(0);
    setHistory([]);
    setMemWrites([]);
    setEmuRegs(EMU_STEPS[0].regs);
    let i = 0;
    const iv = setInterval(() => {
      i++;
      if (i >= EMU_STEPS.length) { clearInterval(iv); setRunning(false); return; }
      setStep(i);
      setEmuRegs(EMU_STEPS[i].regs);
      setHistory(prev => [...prev, EMU_STEPS[i].inst]);
      setMemWrites(prev => [...prev, ...EMU_STEPS[i].mem]);
    }, speed);
  };

  const doStepOne = () => {
    const next = step + 1;
    if (next >= EMU_STEPS.length) return;
    setStep(next);
    setEmuRegs(EMU_STEPS[next].regs);
    setHistory(prev => [...prev, EMU_STEPS[next].inst]);
    setMemWrites(prev => [...prev, ...EMU_STEPS[next].mem]);
  };

  const doReset = () => { setStep(-1); setRunning(false); setEmuRegs(null); setHistory([]); setMemWrites([]); };

  const fmtHex = (n) => typeof n === 'number' ? '0x' + n.toString(16).padStart(8, '0').toUpperCase() : String(n);

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Play size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Emulation Engine</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— x86 Instruction Emulator (Unicorn Engine API)</span>
      </div>

      <div style={{ display: 'flex', gap: 4, marginBottom: 14, alignItems: 'center' }}>
        <button onClick={doRun} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.12)', color: '#22c55e', cursor: running ? 'not-allowed' : 'pointer', fontWeight: 600 }}>▶ Run All</button>
        <button onClick={doStepOne} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: running ? 'not-allowed' : 'pointer' }}>⏭ Step</button>
        <button onClick={doReset} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer' }}>↺ Reset</button>
        <div style={{ marginLeft: 16, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 10, color: '#8b949e' }}>Hız:</span>
          <input type="range" min={50} max={1000} step={50} value={speed} onChange={e => setSpeed(Number(e.target.value))} style={{ width: 80 }} />
          <span style={{ fontSize: 10, color: '#8b949e', fontFamily: 'monospace' }}>{speed}ms</span>
        </div>
        {step >= 0 && <span style={{ marginLeft: 'auto', fontSize: 10, color: '#818cf8' }}>Step {step + 1} / {EMU_STEPS.length}</span>}
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {/* Emulation Code */}
        <Card style={{ flex: 2, minWidth: 350 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Emulation Trace</div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, maxHeight: 340, overflowY: 'auto', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
            {EMU_STEPS.map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 10px',
                background: i === step ? 'rgba(99,102,241,0.15)' : i < step ? 'rgba(34,197,94,0.04)' : 'transparent',
                borderLeft: i === step ? '3px solid #818cf8' : i < step ? '3px solid rgba(34,197,94,0.3)' : '3px solid transparent'
              }}>
                <span style={{ color: i < step ? '#22c55e' : i === step ? '#818cf8' : '#6e7681', fontSize: 9, minWidth: 12 }}>
                  {i < step ? '✓' : i === step ? '▸' : ' '}
                </span>
                <span style={{ color: '#818cf8', minWidth: 80 }}>{MOCK_DEBUG_DISASM[i]?.addr || ''}</span>
                <span style={{ color: i === step ? '#e6edf3' : '#8b949e', fontWeight: i === step ? 700 : 400 }}>{s.inst}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Registers */}
        <div style={{ flex: 1, minWidth: 220, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Registers (x86)</div>
            {emuRegs ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10 }}>
                {Object.entries(emuRegs).map(([k, v]) => {
                  const prev = step > 0 ? EMU_STEPS[step - 1]?.regs[k] : undefined;
                  const changed = prev !== undefined && prev !== v;
                  return (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '1px 4px', borderRadius: 3, background: changed ? 'rgba(245,158,11,0.1)' : (k === 'EIP' ? 'rgba(99,102,241,0.1)' : 'transparent') }}>
                      <span style={{ color: k === 'EIP' ? '#818cf8' : k === 'EFLAGS' ? '#f59e0b' : '#8b949e', fontWeight: 600, minWidth: 52 }}>{k}</span>
                      <span style={{ color: changed ? '#f59e0b' : '#e6edf3' }}>{fmtHex(v)}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ fontSize: 10, color: '#6e7681', padding: 10, textAlign: 'center' }}>Emülasyonu başlatın</div>
            )}
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Bellek Yazmaları</div>
            {memWrites.length > 0 ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 150, overflowY: 'auto' }}>
                {memWrites.map((m, i) => (
                  <div key={i} style={{ display: 'flex', gap: 6, padding: '1px 0' }}>
                    <span style={{ color: '#f87171', minWidth: 80 }}>{m.addr}</span>
                    <span style={{ color: '#e6edf3' }}>← {m.val}</span>
                    <span style={{ color: '#6e7681', fontSize: 9 }}>{m.note}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: 10, color: '#6e7681', textAlign: 'center', padding: 10 }}>Henüz yazma yok</div>
            )}
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Execution Log</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 100, overflowY: 'auto', color: '#8b949e' }}>
              {history.length > 0 ? history.map((h, i) => (
                <div key={i} style={{ color: '#22c55e' }}>✓ {h}</div>
              )) : <div style={{ color: '#6e7681' }}>Bekleniyor...</div>}
            </div>
          </Card>
        </div>
      </div>

      <Card style={{ marginTop: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>ℹ Emülasyon Hakkında</div>
        <div style={{ fontSize: 10, color: '#8b949e', lineHeight: '18px' }}>
          Bu panel, Unicorn Engine API üzerinden x86/x64 talimatlarını emüle eder. Obfuscated kod çözümlemesi, unpacking, API çağrı takibi ve dinamik analiz için kullanılır.
          Gerçek emülasyon için Rust tarafında <code style={{ color: '#818cf8' }}>unicorn-engine</code> crate'i entegre edilmelidir.
        </div>
      </Card>
    </div>
  );
}

// ── 6.4 Ağ Trafiği Yakalama ──────────────────────────────────────

const MOCK_NETWORK = [
  { id: 1, time: '00:00.124', proto: 'DNS', src: '192.168.1.100', dst: '8.8.8.8', port: 53, data: 'A malware-c2.evil.com', size: 62, flag: 'suspicious' },
  { id: 2, time: '00:00.340', proto: 'DNS', src: '8.8.8.8', dst: '192.168.1.100', port: 53, data: 'A → 185.234.72.19', size: 78, flag: 'suspicious' },
  { id: 3, time: '00:00.512', proto: 'TCP', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'SYN → :443 (TLS handshake)', size: 54, flag: 'suspicious' },
  { id: 4, time: '00:00.680', proto: 'TLS', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'Client Hello — SNI: malware-c2.evil.com', size: 284, flag: 'malicious' },
  { id: 5, time: '00:01.020', proto: 'TLS', src: '185.234.72.19', dst: '192.168.1.100', port: 443, data: 'Server Hello — Self-signed cert (CN=localhost)', size: 1024, flag: 'malicious' },
  { id: 6, time: '00:01.340', proto: 'HTTP', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'POST /gate.php — {"id":"BOT-3104","os":"Win10","arch":"x86"}', size: 186, flag: 'malicious' },
  { id: 7, time: '00:01.780', proto: 'HTTP', src: '185.234.72.19', dst: '192.168.1.100', port: 443, data: '200 OK — {"cmd":"download","url":"http://dl.evil.com/payload.bin"}', size: 342, flag: 'malicious' },
  { id: 8, time: '00:02.100', proto: 'DNS', src: '192.168.1.100', dst: '8.8.8.8', port: 53, data: 'A dl.evil.com', size: 48, flag: 'suspicious' },
  { id: 9, time: '00:02.450', proto: 'HTTP', src: '192.168.1.100', dst: '91.215.100.42', port: 80, data: 'GET /payload.bin — downloading 2nd stage', size: 48, flag: 'malicious' },
  { id: 10, time: '00:03.200', proto: 'HTTP', src: '91.215.100.42', dst: '192.168.1.100', port: 80, data: '200 OK — Content-Length: 245760 (MZ header detected)', size: 245760, flag: 'malicious' },
  { id: 11, time: '00:04.000', proto: 'TCP', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'POST /gate.php — {"status":"stage2_loaded","size":245760}', size: 124, flag: 'malicious' },
  { id: 12, time: '00:05.500', proto: 'DNS', src: '192.168.1.100', dst: '8.8.8.8', port: 53, data: 'A update.microsoft.com (legitimate check)', size: 56, flag: 'clean' },
  { id: 13, time: '00:06.200', proto: 'TCP', src: '192.168.1.100', dst: '52.184.220.48', port: 443, data: 'TLS → update.microsoft.com (Windows Update)', size: 512, flag: 'clean' },
  { id: 14, time: '00:08.100', proto: 'UDP', src: '192.168.1.100', dst: '185.234.72.19', port: 4444, data: 'Encrypted beacon — 32 bytes (possible heartbeat)', size: 32, flag: 'malicious' },
  { id: 15, time: '00:10.300', proto: 'ICMP', src: '192.168.1.100', dst: '185.234.72.19', port: 0, data: 'Echo request — covert channel (unusual ICMP payload size: 256)', size: 256, flag: 'suspicious' },
];

function NetworkCapturePage() {
  const [packets, setPackets] = useState(MOCK_NETWORK);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedPkt, setSelectedPkt] = useState(null);
  const [capturing, setCapturing] = useState(false);

  const filtered = useMemo(() => {
    return packets.filter(p => {
      if (filter !== 'all' && p.flag !== filter) return false;
      if (search && !p.data.toLowerCase().includes(search.toLowerCase()) && !p.src.includes(search) && !p.dst.includes(search) && !p.proto.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [packets, filter, search]);

  const stats = useMemo(() => {
    const mal = packets.filter(p => p.flag === 'malicious').length;
    const sus = packets.filter(p => p.flag === 'suspicious').length;
    const cln = packets.filter(p => p.flag === 'clean').length;
    const totalSize = packets.reduce((a, p) => a + p.size, 0);
    const protos = {};
    packets.forEach(p => { protos[p.proto] = (protos[p.proto] || 0) + 1; });
    return { mal, sus, cln, total: packets.length, totalSize, protos };
  }, [packets]);

  const flagColor = (f) => f === 'malicious' ? '#f87171' : f === 'suspicious' ? '#f59e0b' : '#22c55e';
  const protoColor = (p) => ({ DNS: '#60a5fa', TCP: '#8b949e', TLS: '#a78bfa', HTTP: '#f59e0b', UDP: '#22c55e', ICMP: '#f87171' }[p] || '#8b949e');

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Network size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Network Capture</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Sandbox Ağ Analizi</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          {capturing && <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f87171', boxShadow: '0 0 6px #f8717166', animation: '_sp 1s linear infinite', display: 'inline-block' }} />}
          <button onClick={() => setCapturing(!capturing)}
            style={{ fontSize: 10, padding: '4px 12px', borderRadius: 5, border: `1px solid ${capturing ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`, background: capturing ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)', color: capturing ? '#f87171' : '#22c55e', cursor: 'pointer', fontWeight: 600 }}>
            {capturing ? '⏹ Stop' : '● Capture'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        {[
          { label: 'Toplam', value: stats.total, color: '#818cf8' },
          { label: 'Malicious', value: stats.mal, color: '#f87171' },
          { label: 'Suspicious', value: stats.sus, color: '#f59e0b' },
          { label: 'Clean', value: stats.cln, color: '#22c55e' },
          { label: 'Boyut', value: stats.totalSize > 1024 ? (stats.totalSize / 1024).toFixed(1) + ' KB' : stats.totalSize + ' B', color: '#8b949e' },
        ].map((s, i) => (
          <div key={i} style={{ padding: '8px 16px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center', minWidth: 80 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
            <div style={{ fontSize: 9, color: '#6e7681' }}>{s.label}</div>
          </div>
        ))}
        {Object.entries(stats.protos).map(([p, c]) => (
          <div key={p} style={{ padding: '8px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center' }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: protoColor(p), fontFamily: 'monospace' }}>{c}</div>
            <div style={{ fontSize: 9, color: '#6e7681' }}>{p}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        <Search size={13} color="#8b949e" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="IP, protokol veya içerik ara..." style={{ flex: 1, maxWidth: 320, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
        {['all', 'malicious', 'suspicious', 'clean'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: `1px solid ${filter === f ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: filter === f ? 'rgba(99,102,241,0.12)' : 'transparent', color: filter === f ? '#818cf8' : '#8b949e', cursor: 'pointer', textTransform: 'capitalize' }}>{f}</button>
        ))}
      </div>

      {/* Packet Table */}
      <Card>
        <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 400, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>#</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Time</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Proto</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Source</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Destination</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Data</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Flag</th>
            </tr></thead>
            <tbody>
              {filtered.map(p => (
                <tr key={p.id} onClick={() => setSelectedPkt(p)} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', cursor: 'pointer', background: selectedPkt?.id === p.id ? 'rgba(99,102,241,0.08)' : '' }}
                  onMouseOver={e => { if (selectedPkt?.id !== p.id) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                  onMouseOut={e => { if (selectedPkt?.id !== p.id) e.currentTarget.style.background = ''; }}>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#6e7681' }}>{p.id}</td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#8b949e', fontSize: 10 }}>{p.time}</td>
                  <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${protoColor(p.proto)}15`, color: protoColor(p.proto) }}>{p.proto}</span></td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3', fontSize: 10 }}>{p.src}:{p.port}</td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3', fontSize: 10 }}>{p.dst}:{p.port}</td>
                  <td style={{ padding: '4px 8px', color: '#c9d1d9', fontSize: 10, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.data}</td>
                  <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${flagColor(p.flag)}18`, color: flagColor(p.flag), fontWeight: 600 }}>{p.flag}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selectedPkt && (
          <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: '#0d1117', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Paket Detayı — #{selectedPkt.id}</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
              <div><span style={{ color: '#8b949e' }}>Proto: </span><span style={{ color: protoColor(selectedPkt.proto) }}>{selectedPkt.proto}</span></div>
              <div><span style={{ color: '#8b949e' }}>Size: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.size} bytes</span></div>
              <div><span style={{ color: '#8b949e' }}>Src: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.src}:{selectedPkt.port}</span></div>
              <div><span style={{ color: '#8b949e' }}>Dst: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.dst}:{selectedPkt.port}</span></div>
              <div style={{ gridColumn: '1/3' }}><span style={{ color: '#8b949e' }}>Data: </span><span style={{ color: flagColor(selectedPkt.flag) }}>{selectedPkt.data}</span></div>
              <div><span style={{ color: '#8b949e' }}>Flag: </span><span style={{ color: flagColor(selectedPkt.flag), fontWeight: 700 }}>{selectedPkt.flag.toUpperCase()}</span></div>
              <div><span style={{ color: '#8b949e' }}>Time: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.time}</span></div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

// ── 6.5 FLIRT İmza Veritabanı ─────────────────────────────────────

const FLIRT_SIGNATURES = [
  { id: 'msvcrt_printf', pattern: '558BEC8B4508..FF15', name: 'printf', lib: 'MSVCRT', confidence: 98, category: 'CRT', desc: 'Standard C printf — format string output' },
  { id: 'msvcrt_malloc', pattern: '558BEC8B4508..E8', name: 'malloc', lib: 'MSVCRT', confidence: 95, category: 'CRT', desc: 'Heap allocation via CRT' },
  { id: 'msvcrt_free', pattern: '558BEC8B450850..FF15', name: 'free', lib: 'MSVCRT', confidence: 94, category: 'CRT', desc: 'Heap deallocation via CRT' },
  { id: 'msvcrt_memcpy', pattern: '558BEC578B7D0C8B750856', name: 'memcpy', lib: 'MSVCRT', confidence: 97, category: 'CRT', desc: 'Memory copy — potential buffer overflow' },
  { id: 'msvcrt_strlen', pattern: '558BEC8B4508..8A0884C975', name: 'strlen', lib: 'MSVCRT', confidence: 92, category: 'CRT', desc: 'String length calculation' },
  { id: 'ws2_socket', pattern: '558BEC6A..6A..6A..FF15', name: 'socket', lib: 'WS2_32', confidence: 88, category: 'Network', desc: 'Create network socket' },
  { id: 'ws2_connect', pattern: '558BEC8B45..6A10..FF15', name: 'connect', lib: 'WS2_32', confidence: 85, category: 'Network', desc: 'Connect to remote host' },
  { id: 'ws2_send', pattern: '558BEC8B45..6A00..FF15', name: 'send', lib: 'WS2_32', confidence: 86, category: 'Network', desc: 'Send data over socket' },
  { id: 'ws2_recv', pattern: '558BEC8B4508..8B4D0C..FF15', name: 'recv', lib: 'WS2_32', confidence: 84, category: 'Network', desc: 'Receive data from socket' },
  { id: 'advapi_RegOpenKey', pattern: '558BEC..6A..8D45..50FF15', name: 'RegOpenKeyExA', lib: 'ADVAPI32', confidence: 82, category: 'Registry', desc: 'Open registry key — persistence indicator' },
  { id: 'advapi_RegSetValue', pattern: '558BEC..6A..8D4D..51FF15', name: 'RegSetValueExA', lib: 'ADVAPI32', confidence: 80, category: 'Registry', desc: 'Set registry value — malware persistence' },
  { id: 'kernel32_CreateFile', pattern: '558BEC6A00..6A..6A..8B45..50FF15', name: 'CreateFileA', lib: 'KERNEL32', confidence: 91, category: 'FileIO', desc: 'Create or open file' },
  { id: 'kernel32_WriteFile', pattern: '558BEC8D45..506A..8B4D..51FF15', name: 'WriteFile', lib: 'KERNEL32', confidence: 89, category: 'FileIO', desc: 'Write data to file' },
  { id: 'kernel32_VirtualAlloc', pattern: '558BEC6A40..6A..6A00..FF15', name: 'VirtualAlloc', lib: 'KERNEL32', confidence: 93, category: 'Memory', desc: 'Allocate virtual memory — shellcode/packing' },
  { id: 'kernel32_VirtualProtect', pattern: '558BEC8D45..506A..8B4D..51FF15', name: 'VirtualProtect', lib: 'KERNEL32', confidence: 90, category: 'Memory', desc: 'Change memory protection — DEP bypass' },
  { id: 'kernel32_CreateThread', pattern: '558BEC6A008B45..508B4D..51FF15', name: 'CreateRemoteThread', lib: 'KERNEL32', confidence: 87, category: 'Process', desc: 'Create thread in remote process — injection' },
  { id: 'ntdll_NtUnmapView', pattern: '4C8BD1B8..000000', name: 'NtUnmapViewOfSection', lib: 'NTDLL', confidence: 78, category: 'Process', desc: 'Unmap section — process hollowing' },
  { id: 'crypt32_CryptEncrypt', pattern: '558BEC8B45..8B4D..508B55..52FF15', name: 'CryptEncryptMessage', lib: 'CRYPT32', confidence: 81, category: 'Crypto', desc: 'Encrypt message via CryptoAPI' },
  { id: 'openssl_aes_init', pattern: '558BEC83EC..8B45088945..C745', name: 'AES_set_encrypt_key', lib: 'OpenSSL', confidence: 75, category: 'Crypto', desc: 'AES key schedule initialization' },
  { id: 'zlib_inflate', pattern: '558BEC81EC..0000008B4508', name: 'inflate', lib: 'ZLIB', confidence: 83, category: 'Compression', desc: 'Decompress data — packer unpacking' },
];

function FlirtPage() {
  const [search, setSearch] = useState('');
  const [catFilter, setCatFilter] = useState('all');
  const [matchResults, setMatchResults] = useState(null);
  const [scanning, setScanning] = useState(false);

  const categories = useMemo(() => {
    const cats = new Set(FLIRT_SIGNATURES.map(s => s.category));
    return ['all', ...Array.from(cats)];
  }, []);

  const filtered = useMemo(() => {
    return FLIRT_SIGNATURES.filter(s => {
      if (catFilter !== 'all' && s.category !== catFilter) return false;
      if (search && !s.name.toLowerCase().includes(search.toLowerCase()) && !s.lib.toLowerCase().includes(search.toLowerCase()) && !s.desc.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [search, catFilter]);

  const doScan = () => {
    setScanning(true);
    setTimeout(() => {
      const matched = FLIRT_SIGNATURES.filter(() => Math.random() > 0.4).map(s => ({
        ...s,
        addr: '0x' + (0x401000 + Math.floor(Math.random() * 0x5000)).toString(16).padStart(8, '0'),
        matchScore: Math.floor(s.confidence * (0.85 + Math.random() * 0.15)),
      }));
      setMatchResults(matched);
      setScanning(false);
    }, 800);
  };

  const catColor = (c) => ({ CRT: '#60a5fa', Network: '#f87171', Registry: '#f59e0b', FileIO: '#22c55e', Memory: '#a78bfa', Process: '#f87171', Crypto: '#818cf8', Compression: '#8b949e' }[c] || '#8b949e');

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <FileSearch size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>FLIRT Signatures</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Kütüphane Fonksiyon Tanıma (IDA FLIRT uyumlu)</span>
        <button onClick={doScan} disabled={scanning} style={{ marginLeft: 'auto', fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: scanning ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
          {scanning ? '⏳ Taranıyor...' : '🔍 Binary\'de Ara'}
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <Search size={13} color="#8b949e" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Fonksiyon, kütüphane veya açıklama ara..." style={{ flex: 1, maxWidth: 300, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
        {categories.map(c => (
          <button key={c} onClick={() => setCatFilter(c)}
            style={{ fontSize: 9, padding: '3px 8px', borderRadius: 5, border: `1px solid ${catFilter === c ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: catFilter === c ? 'rgba(99,102,241,0.12)' : 'transparent', color: catFilter === c ? '#818cf8' : '#8b949e', cursor: 'pointer' }}>{c}</button>
        ))}
      </div>

      {/* Signature Database */}
      <Card>
        <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📚 İmza Veritabanı ({filtered.length} / {FLIRT_SIGNATURES.length})</div>
        <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 350, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Function</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Library</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Category</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Pattern</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Confidence</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Description</th>
            </tr></thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                  onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                  onMouseOut={e => e.currentTarget.style.background = ''}>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8', fontWeight: 600 }}>{s.name}</td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3' }}>{s.lib}</td>
                  <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${catColor(s.category)}15`, color: catColor(s.category) }}>{s.category}</span></td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#6e7681', fontSize: 9 }}>{s.pattern.substring(0, 18)}...</td>
                  <td style={{ padding: '4px 8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <div style={{ width: 40, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.06)' }}>
                        <div style={{ width: `${s.confidence}%`, height: '100%', borderRadius: 2, background: s.confidence >= 90 ? '#22c55e' : s.confidence >= 80 ? '#f59e0b' : '#f87171' }} />
                      </div>
                      <span style={{ fontSize: 9, color: '#8b949e' }}>{s.confidence}%</span>
                    </div>
                  </td>
                  <td style={{ padding: '4px 8px', color: '#8b949e', fontSize: 10 }}>{s.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Match Results */}
      {matchResults && (
        <Card style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>✅ Eşleşme Sonuçları — {matchResults.length} fonksiyon tanındı</div>
          <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 250, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead><tr style={{ background: 'rgba(34,197,94,0.04)', position: 'sticky', top: 0, zIndex: 1 }}>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Address</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Function</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Library</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Category</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Match</th>
              </tr></thead>
              <tbody>
                {matchResults.sort((a, b) => parseInt(a.addr, 16) - parseInt(b.addr, 16)).map((m, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8' }}>{m.addr}</td>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3', fontWeight: 600 }}>{m.name}</td>
                    <td style={{ padding: '4px 8px', color: '#8b949e' }}>{m.lib}</td>
                    <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${catColor(m.category)}15`, color: catColor(m.category) }}>{m.category}</span></td>
                    <td style={{ padding: '4px 8px' }}>
                      <span style={{ fontSize: 10, fontWeight: 600, color: m.matchScore >= 90 ? '#22c55e' : m.matchScore >= 80 ? '#f59e0b' : '#f87171' }}>{m.matchScore}%</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}


// FAZ 4.6 — i18n altyapısı
// ═══════════════════════════════════════════════════════════════════

const LANG_KEY = 'dissect_lang';
const LANGS = {
  tr: {
    scanner: 'Collector Layer', patcher: 'Hex Patcher', disasm: 'Disassembly', chat: 'AI Chat',
    system: 'System & Models', plugins: 'Plugins', dashboard: 'Dashboard',
    scanComplete: 'Tarama Tamamlandı', risk: 'Risk', clean: 'Temiz', moderate: 'Orta', high: 'Yüksek',
    overview: 'Genel Bakış', strings: 'Stringler', imports: 'İmportlar', sections: 'Bölümler',
    entropy: 'Entropi', yara: 'YARA', hashes: 'Hash\'ler', diff: 'Fark',
    search: 'Ara', filter: 'Filtre', export: 'Dışa Aktar', report: 'Rapor',
    totalScans: 'Toplam Tarama', avgRisk: 'Ortalama Risk', timeline: 'Zaman Çizelgesi',
    projects: 'Projeler', create: 'Oluştur', delete: 'Sil', noData: 'Veri yok',
  },
  en: {
    scanner: 'Collector Layer', patcher: 'Hex Patcher', disasm: 'Disassembly', chat: 'AI Chat',
    system: 'System & Models', plugins: 'Plugins', dashboard: 'Dashboard',
    scanComplete: 'Scan Complete', risk: 'Risk', clean: 'Clean', moderate: 'Moderate', high: 'High',
    overview: 'Overview', strings: 'Strings', imports: 'Imports', sections: 'Sections',
    entropy: 'Entropy', yara: 'YARA', hashes: 'Hashes', diff: 'Diff',
    search: 'Search', filter: 'Filter', export: 'Export', report: 'Report',
    totalScans: 'Total Scans', avgRisk: 'Average Risk', timeline: 'Timeline',
    projects: 'Projects', create: 'Create', delete: 'Delete', noData: 'No data',
  },
};

function useLang() {
  const [lang, setLangState] = useState(() => localStorage.getItem(LANG_KEY) || 'tr');
  const setLang = (l) => { setLangState(l); localStorage.setItem(LANG_KEY, l); };
  const t = LANGS[lang] || LANGS.tr;
  return { lang, setLang, t };
}

const VIEWS = { SCANNER: 'scanner', PATCHER: 'patcher', DISASM: 'disasm', SYSTEM: 'system', CHAT: 'chat', PLUGINS: 'plugins', DASHBOARD: 'dashboard', ATTACH: 'attach', DEBUGGER: 'debugger', EMULATION: 'emulation', NETWORK: 'network', FLIRT: 'flirt' };

// —�—�—� Themes (52) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�
const THEMES = {
  dark:    { bg: '#0d1117', sidebar: '#010409', accent: '#6366f1', accentL: '#818cf8', border: 'rgba(255,255,255,0.06)' },
  red:     { bg: '#0d0707', sidebar: '#080101', accent: '#ef4444', accentL: '#f87171', border: 'rgba(239,68,68,0.12)' },
  ocean:   { bg: '#030c18', sidebar: '#020810', accent: '#0ea5e9', accentL: '#38bdf8', border: 'rgba(14,165,233,0.12)' },
  // G5 — High contrast accessibility theme
  hicontrast: { bg: '#000000', sidebar: '#0a0a0a', accent: '#ffffff', accentL: '#ffffff', border: 'rgba(255,255,255,0.3)' },
};

export default function App() {
  const [view, setView]               = useState(VIEWS.SCANNER);
  const [isMaximized, setIsMaximized] = useState(false);
  const [chatContexts, setChatContexts] = useState([]); // multi-context collector
  const [theme, setTheme]             = useState(() => localStorage.getItem('dissect_theme') || 'dark'); // 52
  const [zoom, setZoom]               = useState(() => parseFloat(localStorage.getItem('dissect_zoom') || '1')); // 54
  const [scanHistory, setScanHistory] = useState([]); // C7 — bağlamsal geçmiş
  const [disasmFilePath, setDisasmFilePath] = useState(null); // 1.1 — file for disassembly view
  const [cmdOpen, setCmdOpen]         = useState(false); // G6 — command palette
  const [cmdQuery, setCmdQuery]       = useState('');    // G6
  // G1 — Resizable sidebar
  const [sidebarWidth, setSidebarWidth] = useState(() => parseInt(localStorage.getItem('dissect_sbw') || '196'));
  const [sidebarDragging, setSidebarDragging] = useState(false);
  // G7 — Onboarding tour (show on first launch)
  const [tourStep, setTourStep]       = useState(() => {
    if (localStorage.getItem('dissect_tour_done')) return -1;
    return 0;
  });
  const appWindow = getCurrentWindow();
  const T = THEMES[theme] || THEMES.dark;

  const handleMaximize = async () => {
    await appWindow.toggleMaximize();
    setIsMaximized(await appWindow.isMaximized());
  };

  const sendToAI = (result, fileName) => {
    setScanHistory(h => {
      const entry = { fileName, sha256: result.sha256, riskScore: result.riskScore, arch: result.arch, denuvo: result.denuvo, vmp: result.vmp, antiDebug: result.antiDebug, packers: result.packers };
      return [entry, ...h].slice(0, 5);
    });
    sendToChat({ type: 'pe_analyst', fileName, ...result });
  };

  const sendToChat = (ctx) => {
    const id = Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    setChatContexts(prev => [...prev, { ...ctx, _id: id, _selected: true, _ts: Date.now() }]);
    setView(VIEWS.CHAT);
  };

  const openInDisasm = (filePath) => {
    setDisasmFilePath(filePath);
    setView(VIEWS.DISASM);
  };

  // 49 — Keyboard shortcuts
  useEffect(() => {
    const VLIST = [VIEWS.SCANNER, VIEWS.PATCHER, VIEWS.DISASM, VIEWS.CHAT, VIEWS.SYSTEM, VIEWS.PLUGINS, VIEWS.DASHBOARD];
    const handler = (e) => {
      if (e.ctrlKey && !e.altKey && !e.shiftKey && !e.metaKey) {
        if (e.key >= '1' && e.key <= '6') { e.preventDefault(); setView(VLIST[parseInt(e.key) - 1]); }
        if (e.key === 'k') { e.preventDefault(); setCmdOpen(v => !v); setCmdQuery(''); } // G6
      }
      if (e.key === 'Escape') { setCmdOpen(false); } // G6
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // 54 — Zoom with Ctrl+Wheel
  useEffect(() => {
    const handler = (e) => {
      if (e.ctrlKey) {
        e.preventDefault();
        setZoom(prev => {
          const next = Math.min(1.5, Math.max(0.7, prev + (e.deltaY < 0 ? 0.05 : -0.05)));
          localStorage.setItem('dissect_zoom', String(next));
          return Math.round(next * 100) / 100;
        });
      }
    };
    window.addEventListener('wheel', handler, { passive: false });
    return () => window.removeEventListener('wheel', handler);
  }, []);

  // 51 — Window size memory
  useEffect(() => {
    const saved = localStorage.getItem('dissect_winsize');
    if (saved) {
      try {
        const { w, h } = JSON.parse(saved);
        appWindow.setSize({ type: 'Logical', width: w, height: h }).catch(() => {});
      } catch {}
    }
    const onResize = async () => {
      try {
        const sz = await appWindow.innerSize();
        localStorage.setItem('dissect_winsize', JSON.stringify({ w: sz.width, h: sz.height }));
      } catch {}
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  // 52 — persist theme
  useEffect(() => { localStorage.setItem('dissect_theme', theme); }, [theme]);

  // G1 — sidebar resize mouse events
  useEffect(() => {
    if (!sidebarDragging) return;
    const onMove = (e) => {
      const next = Math.min(340, Math.max(140, e.clientX));
      setSidebarWidth(next);
      localStorage.setItem('dissect_sbw', String(Math.round(next)));
    };
    const onUp = () => setSidebarDragging(false);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); };
  }, [sidebarDragging]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', overflow: 'hidden', background: T.bg, color: '#e6edf3', fontFamily: "'Inter','SF Pro Display',system-ui,sans-serif", userSelect: 'none', transform: zoom !== 1 ? `scale(${zoom})` : undefined, transformOrigin: 'top left', ...(zoom !== 1 ? { width: `${100 / zoom}vw`, height: `${100 / zoom}vh` } : {}) }}>

      {/* �"��"� TITLEBAR �"��"� */}
      <style>{`@keyframes _sp { to { transform: rotate(360deg); } }`}</style>
      <div data-tauri-drag-region style={{ display: 'flex', alignItems: 'center', height: 42, flexShrink: 0, background: T.sidebar, borderBottom: `1px solid ${T.border}`, padding: '0 6px 0 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, pointerEvents: 'none' }} data-tauri-drag-region>
          <div style={{ width: 22, height: 22, borderRadius: 6, background: T.accent, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Microscope size={13} color="white" /></div>
          <span style={{ fontSize: 12, fontWeight: 700, color: T.accent, letterSpacing: '0.06em' }}>DISSECT</span>
        </div>
        <div style={{ flex: 1 }} data-tauri-drag-region />
        {/* G6 — Ctrl+K hint in titlebar */}
        <button onClick={() => { setCmdOpen(true); setCmdQuery(''); }}
          style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.05)', color: '#374151', cursor: 'pointer', marginRight: 10, display: 'flex', alignItems: 'center', gap: 5 }}>
          ? <span style={{ letterSpacing: '0.05em' }}>Ctrl+K</span>
        </button>
        {/* 52 — Theme picker */}
        <div style={{ display: 'flex', gap: 4, marginRight: 12 }}>
          {Object.entries(THEMES).map(([k, v]) => (
            <button key={k} onClick={() => setTheme(k)} title={k}
              style={{ width: 14, height: 14, borderRadius: '50%', background: v.accent, border: theme === k ? `2px solid white` : '2px solid transparent', cursor: 'pointer', padding: 0 }} />
          ))}
          {/* zoom indicator */}
          {zoom !== 1 && <span style={{ fontSize: 9, color: '#374151', alignSelf: 'center', marginLeft: 4 }}>{Math.round(zoom * 100)}%</span>}
        </div>
        {/* Window Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <WinBtn onClick={() => appWindow.minimize()}><Minus size={13} /></WinBtn>
          <WinBtn onClick={handleMaximize}>{isMaximized ? <Square size={11} /> : <Maximize2 size={12} />}</WinBtn>
          <WinBtn onClick={() => appWindow.close()} danger><X size={13} /></WinBtn>
        </div>
      </div>

      {/* �"��"� BODY �"��"� */}
      {/* G1 — Resizable sidebar via state-driven width */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

        {/* Sidebar */}
        <aside style={{ width: sidebarWidth, flexShrink: 0, background: T.sidebar, borderRight: `1px solid ${T.border}`, display: 'flex', flexDirection: 'column', padding: '14px 8px', position: 'relative', userSelect: sidebarDragging ? 'none' : undefined }}>
          <NavItem active={view === VIEWS.SCANNER} onClick={() => setView(VIEWS.SCANNER)} icon={<ShieldAlert size={15} />} label="Collector Layer"  sub="PE · Entropy · Strings · Imports" />
          <NavItem active={view === VIEWS.PATCHER} onClick={() => setView(VIEWS.PATCHER)} icon={<Binary size={15} />}     label="Hex Patcher"     sub="Offsets · NOP injection" />
          <NavItem active={view === VIEWS.DISASM}  onClick={() => setView(VIEWS.DISASM)}  icon={<Code size={15} />}       label="Disassembly"     sub="x86/x64 · Functions · XRef" badge="NEW" />

          <NavItem active={view === VIEWS.CHAT}    onClick={() => setView(VIEWS.CHAT)}    icon={<MessageSquare size={15} />} label="AI Chat"       sub="Explain · Analyze · Guide · Hyp." badge="NEW" />
          <NavItem active={view === VIEWS.SYSTEM}  onClick={() => setView(VIEWS.SYSTEM)}  icon={<Cpu size={15} />}        label="System & Models" sub="GPU · CUDA · Model manager" />
          <NavItem active={view === VIEWS.PLUGINS} onClick={() => setView(VIEWS.PLUGINS)} icon={<Layers size={15} />}     label="Plugins"         sub="Mağaza · API · Sandbox" badge="v2" />
          <NavItem active={view === VIEWS.DASHBOARD} onClick={() => setView(VIEWS.DASHBOARD)} icon={<BarChart2 size={15} />} label="Dashboard"       sub="İstatistik · Rapor · Proje" badge="NEW" />

          <div style={{ height: 1, background: 'rgba(255,255,255,0.04)', margin: '8px 4px' }} />
          <div style={{ fontSize: 9, color: '#6e7681', padding: '2px 12px', marginBottom: 2 }}>ADVANCED</div>
          <NavItem active={view === VIEWS.ATTACH}    onClick={() => setView(VIEWS.ATTACH)}    icon={<Monitor size={15} />}      label="Process Attach"  sub="Bellek · Bölge · Okuma" badge="v6" />
          <NavItem active={view === VIEWS.DEBUGGER}  onClick={() => setView(VIEWS.DEBUGGER)}  icon={<Terminal size={15} />}     label="Debugger"        sub="Step · Break · Register" badge="v6" />
          <NavItem active={view === VIEWS.EMULATION} onClick={() => setView(VIEWS.EMULATION)} icon={<Play size={15} />}        label="Emulation"       sub="x86 Emülatör · Unicorn" badge="v6" />
          <NavItem active={view === VIEWS.NETWORK}   onClick={() => setView(VIEWS.NETWORK)}   icon={<Network size={15} />}     label="Net Capture"     sub="DNS · HTTP · TLS · Beacon" badge="v6" />
          <NavItem active={view === VIEWS.FLIRT}     onClick={() => setView(VIEWS.FLIRT)}     icon={<FileSearch size={15} />}  label="FLIRT Sigs"      sub="Kütüphane · İmza · IDA" badge="v6" />

          <div style={{ flex: 1 }} />
          <div style={{ padding: '10px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e66' }} />
              <span style={{ fontSize: 10, color: '#2d3748', fontWeight: 500 }}>Dissect — Active</span>
            </div>
            <div style={{ fontSize: 9, color: '#1a1f2e' }}>Collector · Analyzer · AI Layer · Local</div>
          </div>
          {/* G1 — Drag handle */}
          <div
            onMouseDown={e => { e.preventDefault(); setSidebarDragging(true); }}
            style={{ position: 'absolute', right: 0, top: 0, bottom: 0, width: 5, cursor: 'col-resize', background: sidebarDragging ? 'rgba(99,102,241,0.4)' : 'transparent', transition: 'background 0.15s', zIndex: 10 }}
            title="Drag to resize sidebar" />
        </aside>

        {/* Main */}
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', background: T.bg }}>
          {view === VIEWS.SCANNER && <ScannerPage onSendToAI={sendToAI} onSendToChat={sendToChat} onOpenDisasm={openInDisasm} />}
          {view === VIEWS.PATCHER && <PatcherPage onSendToChat={sendToChat} />}
          {view === VIEWS.DISASM  && <DisassemblyPage filePath={disasmFilePath} onSendToChat={sendToChat} />}

          <div style={{ flex: 1, display: view === VIEWS.CHAT ? 'flex' : 'none', flexDirection: 'column', overflow: 'hidden' }}>
            <ChatPage chatContexts={chatContexts} setChatContexts={setChatContexts} scanHistory={scanHistory} />
          </div>
          {view === VIEWS.SYSTEM  && <SystemPage />}
          {view === VIEWS.PLUGINS && <PluginPage />}
          {view === VIEWS.DASHBOARD && <DashboardPage />}
          {view === VIEWS.ATTACH    && <ProcessAttachPage />}
          {view === VIEWS.DEBUGGER  && <DebuggerPage />}
          {view === VIEWS.EMULATION && <EmulationPage />}
          {view === VIEWS.NETWORK   && <NetworkCapturePage />}
          {view === VIEWS.FLIRT     && <FlirtPage />}
        </main>

      </div>

      {/* G7 — Onboarding Tour (first launch) */}
      {tourStep >= 0 && (() => {
        const STEPS = [
          { icon: '🔬', title: 'Hoş Geldiniz — Dissect v2', body: 'Dissect, Windows PE binary analizi ve AI destekli tersine mühendislik stüdyosudur. Beş ana modül içerir.' },
          { icon: '✎', title: 'Scanner', body: 'Herhangi bir .exe, .dll veya .sys dosyasını Scanner\'a sürükleyin. SHA-256, entropi, koruma tespiti, imphash ve daha fazlasını otomatik hesaplar.' },
          { icon: '🔧', title: 'Patcher', body: 'Hex Patcher\'da bir dosya açın, offset + patched bytes girerek NOP sled veya JMP patch uygulayın. Backup otomatik alınır.' },
          { icon: '🤖', title: 'AI Analyst', body: 'Scanner sonuçlarını "Send to AI" ile AI Analyst\'e gönderin. LM Studio\'ya bağlanarak yerel model kullanın.' },
          { icon: '⌘', title: 'Hızlı Erişim (Ctrl+K)', body: 'Her özelliğe Ctrl+K komut paleti ile erişin. Ctrl+1⬦6 ile sekmelere geçin. Temayı başlık çubuğundaki renkli noktalardan değiştirin.' },
        ];
        const step = STEPS[tourStep];
        const isLast = tourStep === STEPS.length - 1;
        const done = () => { localStorage.setItem('dissect_tour_done', '1'); setTourStep(-1); };
        return (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 9998, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ width: 440, borderRadius: 18, background: '#0d1117', border: '1px solid rgba(99,102,241,0.35)', boxShadow: '0 30px 80px rgba(0,0,0,0.9)', padding: 32, textAlign: 'center' }}>
              <div style={{ fontSize: 40, marginBottom: 14 }}>{step.icon}</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>{step.title}</div>
              <div style={{ fontSize: 13, color: '#4b5563', lineHeight: 1.7, marginBottom: 22 }}>{step.body}</div>
              {/* Progress dots */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 6, marginBottom: 22 }}>
                {STEPS.map((_, i) => (
                  <div key={i} onClick={() => setTourStep(i)} style={{ width: i === tourStep ? 20 : 8, height: 8, borderRadius: 4, background: i === tourStep ? '#6366f1' : i < tourStep ? '#374151' : '#1f2937', cursor: 'pointer', transition: 'all 0.2s' }} />
                ))}
              </div>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
                <button onClick={done} style={{ fontSize: 12, padding: '7px 18px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', background: 'transparent', color: '#374151', cursor: 'pointer' }}>Atla</button>
                <button onClick={() => isLast ? done() : setTourStep(s => s + 1)}
                  style={{ fontSize: 12, padding: '7px 22px', borderRadius: 8, border: '1px solid rgba(99,102,241,0.4)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>
                  {isLast ? '🚀 Başla' : 'İleri →'}
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* G6 — Command Palette (Ctrl+K) */}
      {cmdOpen && (() => {
        const CMD_LIST = [
          { label: '🔍 Scanner — PE Analiz',      action: () => { setView(VIEWS.SCANNER); setCmdOpen(false); } },
          { label: '🔧 Patcher — Hex Düzenle',    action: () => { setView(VIEWS.PATCHER); setCmdOpen(false); } },
          { label: 'u{1F52C} Analyst (AI Chat)',             action: () => { setView(VIEWS.CHAT);    setCmdOpen(false); } },
          { label: '💬 AI Chat',                   action: () => { setView(VIEWS.CHAT);    setCmdOpen(false); } },
          { label: '⚙️ System & Models',           action: () => { setView(VIEWS.SYSTEM);  setCmdOpen(false); } },
          { label: '🧩 Plugins',                   action: () => { setView(VIEWS.PLUGINS); setCmdOpen(false); } },
          { label: '📊 Dashboard',                  action: () => { setView(VIEWS.DASHBOARD); setCmdOpen(false); } },
          { label: '🎓 Onboarding Turunu Başlat (G7)', action: () => { localStorage.removeItem('dissect_tour_done'); setTourStep(0); setCmdOpen(false); } },
          ...getHistory().slice(0, 5).map(h => ({
            label: `📄 ${h.fileName} — Risk:${h.riskScore} · ${h.arch}`,
            action: () => { setCmdOpen(false); },
          })),
          ...getPluginCommands().map(c => ({
            label: `🧩 ${c.label}`,
            action: () => { c.fn(); setCmdOpen(false); },
          })),
        ];
        const filtered = cmdQuery
          ? CMD_LIST.filter(c => c.label.toLowerCase().includes(cmdQuery.toLowerCase()))
          : CMD_LIST;
        return (
          <div onClick={() => setCmdOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 9999, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: 80 }}>
            <div onClick={e => e.stopPropagation()} style={{ width: 520, borderRadius: 14, background: '#0d1117', border: '1px solid rgba(99,102,241,0.35)', boxShadow: '0 24px 80px rgba(0,0,0,0.8)', overflow: 'hidden' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <span style={{ fontSize: 15 }}>?</span>
                <input autoFocus value={cmdQuery} onChange={e => setCmdQuery(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Escape') { setCmdOpen(false); }
                    if (e.key === 'Enter' && filtered.length > 0) { filtered[0].action(); }
                  }}
                  placeholder="Komut veya sayfa ara⬦ (Esc = kapat)"
                  style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', fontSize: 14, color: '#e2e8f0', fontFamily: 'inherit' }} />
                <span style={{ fontSize: 10, color: '#374151', flexShrink: 0 }}>Ctrl+K</span>
              </div>
              <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                {filtered.length === 0
                  ? <div style={{ padding: '20px', textAlign: 'center', fontSize: 12, color: '#374151' }}>Sonuç bulunamadı</div>
                  : filtered.map((c, i) => (
                    <div key={i} onClick={c.action}
                      style={{ padding: '10px 16px', cursor: 'pointer', fontSize: 13, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 10, transition: 'background 0.1s' }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'rgba(99,102,241,0.1)'; e.currentTarget.style.color = '#e2e8f0'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#94a3b8'; }}>
                      {c.label}
                    </div>
                  ))
                }
              </div>
              <div style={{ padding: '7px 16px', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: 10, color: '#2d3748', display: 'flex', gap: 16 }}>
                <span>↕ Gezin</span><span>? Seç</span><span>Esc Kapat</span>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
