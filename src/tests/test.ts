import Encryptor from "../lib/Encryptor.js";

const encryptor = new Encryptor('hello there bro', { iterations: 250_000 });
const startTime = performance.now();
const encrypted = await encryptor.encrypt("This is a secret!");
const encryptTime = performance.now() - startTime;

const decryptStartTime = performance.now();
const decrypted = await encryptor.decrypt(encrypted);
const decryptTime = performance.now() - decryptStartTime;

console.log('Encrypted:', encrypted);
console.log('Decrypted:', decrypted);
console.log('Encrypt time:', encryptTime.toFixed(2), 'ms');
console.log('Decrypt time:', decryptTime.toFixed(2), 'ms');
