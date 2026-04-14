#!/usr/bin/env node
/**
 * CPA6 Prep · 题库加密/解密工具
 * 算法：AES-256-GCM + PBKDF2-SHA256（100,000次迭代）
 *
 * 用法：
 *   加密：node cpa6-encrypt.js encrypt <input.json> <output.enc> <password>
 *   解密：node cpa6-encrypt.js decrypt <input.enc> <output.json> <password>
 *   验证：node cpa6-encrypt.js verify <input.enc> <password>
 *
 * 示例：
 *   node cpa6-encrypt.js encrypt data/cpa6-full.json data/full.enc MLL-CPA6-FULL-2026
 *   node cpa6-encrypt.js encrypt data/cpa6-demo.json data/demo.enc DEMO2026
 *   node cpa6-encrypt.js verify data/full.enc MLL-CPA6-FULL-2026
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ── 加密参数 ──────────────────────────────────────────────────────────────
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_DIGEST     = 'sha256';
const KEY_LENGTH        = 32;   // 256-bit
const SALT_LENGTH       = 16;   // 128-bit
const IV_LENGTH         = 12;   // 96-bit (GCM 标准)
const TAG_LENGTH        = 16;   // 128-bit auth tag
const ENC_VERSION       = 1;

// ── 核心函数 ──────────────────────────────────────────────────────────────

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(
    Buffer.from(password, 'utf8'),
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST
  );
}

function encrypt(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv   = crypto.randomBytes(IV_LENGTH);
  const key  = deriveKey(password, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return {
    v:    ENC_VERSION,
    salt: salt.toString('base64'),
    iv:   iv.toString('base64'),
    tag:  tag.toString('base64'),
    data: encrypted.toString('base64')
  };
}

function decrypt(encObj, password) {
  if (encObj.v !== ENC_VERSION) {
    throw new Error(`Unsupported version: ${encObj.v}`);
  }
  const salt      = Buffer.from(encObj.salt, 'base64');
  const iv        = Buffer.from(encObj.iv,   'base64');
  const tag       = Buffer.from(encObj.tag,  'base64');
  const encrypted = Buffer.from(encObj.data, 'base64');
  const key       = deriveKey(password, salt);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  try {
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  } catch (e) {
    throw new Error('Decryption failed — wrong password or corrupted file');
  }
}

// ── CLI 命令 ──────────────────────────────────────────────────────────────

const [,, cmd, arg1, arg2, arg3] = process.argv;

if (cmd === 'encrypt') {
  // encrypt <input.json> <output.enc> <password>
  if (!arg1 || !arg2 || !arg3) {
    console.error('Usage: node cpa6-encrypt.js encrypt <input.json> <output.enc> <password>');
    process.exit(1);
  }
  const inputPath  = path.resolve(arg1);
  const outputPath = path.resolve(arg2);
  const password   = arg3;

  if (!fs.existsSync(inputPath)) {
    console.error(`Input file not found: ${inputPath}`);
    process.exit(1);
  }

  const plaintext = fs.readFileSync(inputPath, 'utf8');

  // 验证是合法 JSON
  try {
    const parsed = JSON.parse(plaintext);
    const paperCount = Array.isArray(parsed) ? parsed.length : '?';
    const qCount = Array.isArray(parsed)
      ? parsed.reduce((n, p) => n + (p.questions ? p.questions.length : 0), 0)
      : '?';
    console.log(`✓ Valid JSON: ${paperCount} paper(s), ${qCount} question(s)`);
  } catch (e) {
    console.error('Input is not valid JSON:', e.message);
    process.exit(1);
  }

  const encObj = encrypt(plaintext, password);
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(encObj), 'utf8');

  const inputSize  = fs.statSync(inputPath).size;
  const outputSize = fs.statSync(outputPath).size;
  console.log(`✓ Encrypted: ${inputPath} → ${outputPath}`);
  console.log(`  Input:  ${(inputSize/1024).toFixed(1)} KB`);
  console.log(`  Output: ${(outputSize/1024).toFixed(1)} KB`);
  console.log(`  Password: ${password}`);

} else if (cmd === 'decrypt') {
  // decrypt <input.enc> <output.json> <password>
  if (!arg1 || !arg2 || !arg3) {
    console.error('Usage: node cpa6-encrypt.js decrypt <input.enc> <output.json> <password>');
    process.exit(1);
  }
  const inputPath  = path.resolve(arg1);
  const outputPath = path.resolve(arg2);
  const password   = arg3;

  if (!fs.existsSync(inputPath)) {
    console.error(`Input file not found: ${inputPath}`);
    process.exit(1);
  }

  const encObj = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const plaintext = decrypt(encObj, password);

  fs.writeFileSync(outputPath, plaintext, 'utf8');
  console.log(`✓ Decrypted: ${inputPath} → ${outputPath}`);

} else if (cmd === 'verify') {
  // verify <input.enc> <password>
  if (!arg1 || !arg2) {
    console.error('Usage: node cpa6-encrypt.js verify <input.enc> <password>');
    process.exit(1);
  }
  const inputPath = path.resolve(arg1);
  const password  = arg2;

  if (!fs.existsSync(inputPath)) {
    console.error(`File not found: ${inputPath}`);
    process.exit(1);
  }

  const encObj = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  try {
    const plaintext = decrypt(encObj, password);
    const parsed = JSON.parse(plaintext);
    const paperCount = Array.isArray(parsed) ? parsed.length : '?';
    const qCount = Array.isArray(parsed)
      ? parsed.reduce((n, p) => n + (p.questions ? p.questions.length : 0), 0)
      : '?';
    console.log(`✓ Verified OK: ${paperCount} paper(s), ${qCount} question(s)`);
  } catch (e) {
    console.error(`✗ ${e.message}`);
    process.exit(1);
  }

} else {
  console.log(`
CPA6 Prep · 题库加密工具
=========================
Commands:
  encrypt <input.json> <output.enc> <password>   加密题库
  decrypt <input.enc>  <output.json> <password>  解密题库
  verify  <input.enc>  <password>                验证加密文件

Examples:
  node cpa6-encrypt.js encrypt data/cpa6-full.json data/full.enc MLL-CPA6-FULL-2026
  node cpa6-encrypt.js encrypt data/cpa6-demo.json data/demo.enc DEMO2026
  node cpa6-encrypt.js verify data/full.enc MLL-CPA6-FULL-2026
`);
  process.exit(0);
}
