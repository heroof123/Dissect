// Dissect — Analysis Worker wrapper (promise-based)
// Usage: import { workerAnalyze } from './workerApi';
//        const { entropy, strings, crc32, md5 } = await workerAnalyze(uint8Array);

let _worker = null;
let _idCounter = 0;
const _pending = new Map();

function getWorker() {
  if (!_worker) {
    _worker = new Worker(new URL('./analysis.worker.js', import.meta.url), { type: 'module' });
    _worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const p = _pending.get(id);
      if (p) {
        _pending.delete(id);
        if (error) p.reject(new Error(error));
        else p.resolve(result);
      }
    };
  }
  return _worker;
}

function post(type, data) {
  return new Promise((resolve, reject) => {
    const id = ++_idCounter;
    _pending.set(id, { resolve, reject });
    getWorker().postMessage({ id, type, data }, [data.buffer]);
  });
}

export function workerEntropy(data)  { return post('entropy', data); }
export function workerStrings(data)  { return post('strings', data); }
export function workerCRC32(data)    { return post('crc32', data); }
export function workerMD5(data)      { return post('md5', data); }
export function workerAnalyze(data)  { return post('all', data); }
