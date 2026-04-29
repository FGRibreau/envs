#!/usr/bin/env node
// Bitwarden / Vaultwarden account registration over HTTP.
//
// Bitwarden's signup is a 3-step KDF dance that the official `bw` CLI no
// longer exposes (account creation moved to the web vault). For tests we do
// it ourselves: derive the master key from password+email via PBKDF2,
// produce the masterPasswordHash, encrypt a random user symmetric key, then
// POST /identity/accounts/register.
//
// Usage: node register-account.js
//   env: VAULTWARDEN_URL, RBW_EMAIL, RBW_PASSWORD

const crypto = require('crypto');
const http = require('http');
const https = require('https');

const email = process.env.RBW_EMAIL;
const password = process.env.RBW_PASSWORD;
const baseUrl = process.env.VAULTWARDEN_URL;
const kdfIterations = 600000;

if (!email || !password || !baseUrl) {
    console.error('Missing env: RBW_EMAIL, RBW_PASSWORD, VAULTWARDEN_URL');
    process.exit(2);
}

// 1. PBKDF2(password, email, 600000) → masterKey (32 bytes)
const masterKey = crypto.pbkdf2Sync(password, email.toLowerCase(), kdfIterations, 32, 'sha256');

// 2. PBKDF2(masterKey, password, 1) → masterPasswordHash, then base64
const masterPasswordHash = crypto
    .pbkdf2Sync(masterKey, password, 1, 32, 'sha256')
    .toString('base64');

// 3. HKDF-Expand(masterKey, "enc"|"mac") → stretchedKey (64 bytes)
const hkdfExpand = (prk, info, len) => {
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(Buffer.concat([Buffer.from(info), Buffer.from([1])]));
    return hmac.digest().slice(0, len);
};
const encKey = hkdfExpand(masterKey, 'enc', 32);
const macKey = hkdfExpand(masterKey, 'mac', 32);

// 4. Random 512-bit user symmetric key (32 bytes enc + 32 bytes mac).
const userKey = crypto.randomBytes(64);

// 5. AES-256-CBC encrypt userKey with stretchedKey+iv, then HMAC-SHA256.
//    Bitwarden EncString type 2 = "iv|ciphertext|mac" all base64.
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
const ciphertext = Buffer.concat([cipher.update(userKey), cipher.final()]);
const mac = crypto
    .createHmac('sha256', macKey)
    .update(Buffer.concat([iv, ciphertext]))
    .digest();
const protectedKey = `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`;

const body = JSON.stringify({
    email,
    name: 'envs-tester',
    masterPasswordHash,
    masterPasswordHint: null,
    key: protectedKey,
    kdf: 0,
    kdfIterations,
});

const u = new URL(`${baseUrl}/identity/accounts/register`);
const lib = u.protocol === 'https:' ? https : http;
const req = lib.request(
    {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
        },
    },
    (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
            if (res.statusCode === 200 || res.statusCode === 204) {
                console.log('registered');
                process.exit(0);
            }
            console.error(`register failed (HTTP ${res.statusCode}): ${data}`);
            process.exit(1);
        });
    }
);
req.on('error', (e) => {
    console.error(`register request error: ${e.message}`);
    process.exit(1);
});
req.write(body);
req.end();
