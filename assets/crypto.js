/*
 * 暗号処理の共通モジュール（Web Crypto API のみ使用）
 *
 * - パスワード暗号: PBKDF2-SHA256 で鍵を導出し、AES-GCM(256bit) で暗号化
 * - 鍵暗号:         ランダムな 256bit 鍵で AES-GCM 暗号化（記事本体に使用）
 *
 * 暗号ファイル(.enc)は JSON テキスト:
 *   パスワード暗号 { v, kdf, iter, salt, iv, ct }
 *   鍵暗号         { v, iv, ct }
 */
(function (global) {
  'use strict';

  const ITERATIONS = 600000;
  const te = new TextEncoder();
  const td = new TextDecoder();

  class DecryptError extends Error {
    constructor(message) {
      super(message || '復号できませんでした');
      this.name = 'DecryptError';
    }
  }

  function toB64(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }

  function fromB64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  function randomHex(nBytes) {
    return toHex(randomBytes(nBytes));
  }

  function newSalt() {
    return toB64(randomBytes(16));
  }

  function newKey() {
    return toB64(randomBytes(32));
  }

  // PBKDF2 は重いので、同じパスワード・ソルトの鍵はメモリ上で使い回す
  const derived = new Map();
  function deriveKey(password, saltB64, iterations) {
    const id = saltB64 + '|' + iterations + '|' + password;
    if (!derived.has(id)) {
      const p = (async () => {
        const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: fromB64(saltB64), iterations, hash: 'SHA-256' },
          base,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      })();
      p.catch(() => derived.delete(id));
      derived.set(id, p);
    }
    return derived.get(id);
  }

  async function seal(key, obj) {
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)));
    return { iv: toB64(iv), ct: toB64(ct) };
  }

  async function unseal(key, ivB64, ctB64) {
    let pt;
    try {
      pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ctB64));
    } catch (e) {
      throw new DecryptError();
    }
    return JSON.parse(td.decode(pt));
  }

  function parseFile(text) {
    let f;
    try {
      f = JSON.parse(text);
    } catch (e) {
      throw new Error('暗号ファイルの形式が正しくありません');
    }
    if (!f || f.v !== 1 || typeof f.iv !== 'string' || typeof f.ct !== 'string') {
      throw new Error('暗号ファイルの形式が正しくありません');
    }
    return f;
  }

  async function encryptWithPassword(obj, password, saltB64) {
    const salt = saltB64 || newSalt();
    const key = await deriveKey(password, salt, ITERATIONS);
    const sealed = await seal(key, obj);
    return JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: ITERATIONS, salt, iv: sealed.iv, ct: sealed.ct });
  }

  async function decryptWithPassword(text, password) {
    const f = parseFile(text);
    if (typeof f.salt !== 'string' || !Number.isInteger(f.iter)) {
      throw new Error('暗号ファイルの形式が正しくありません');
    }
    const key = await deriveKey(password, f.salt, f.iter);
    return unseal(key, f.iv, f.ct);
  }

  function importRawKey(keyB64) {
    return crypto.subtle.importKey('raw', fromB64(keyB64), 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function encryptWithKey(obj, keyB64) {
    const sealed = await seal(await importRawKey(keyB64), obj);
    return JSON.stringify({ v: 1, iv: sealed.iv, ct: sealed.ct });
  }

  async function decryptWithKey(text, keyB64) {
    const f = parseFile(text);
    return unseal(await importRawKey(keyB64), f.iv, f.ct);
  }

  // 名前の表記ゆれ（全角半角・前後の空白・大文字小文字）を吸収する
  function normalizeName(name) {
    return String(name || '').normalize('NFKC').trim().toLowerCase();
  }

  // 閲覧者ファイル名。名前そのものがファイル一覧に出ないようハッシュ化する
  async function viewerFileId(name) {
    const h = await crypto.subtle.digest('SHA-256', te.encode('novels:viewer:' + normalizeName(name)));
    return toHex(new Uint8Array(h).slice(0, 16));
  }

  global.NovelCrypto = {
    DecryptError,
    encryptWithPassword,
    decryptWithPassword,
    encryptWithKey,
    decryptWithKey,
    newKey,
    newSalt,
    randomHex,
    normalizeName,
    viewerFileId,
  };
})(typeof window !== 'undefined' ? window : globalThis);
