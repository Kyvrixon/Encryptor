import crypto from 'node:crypto';
/**
 * Encryptor for AES-256-GCM with double-layer encryption and PBKDF2 key derivation.
 */
export default class Encryptor {
    /**
     * Initializes a new instance of the Encryptor class.
     * @param password The encryption/decryption password. Must be at least 5 characters.
     * @param options Optional config: `iterations` for PBKDF2. Minimum 10,000.
     */
    constructor(password, options) {
        if (typeof password !== "string" || password.length < 5) {
            throw new Error("Password must be a non-empty string longer than 5 characters.");
        }
        const iterations = options?.iterations ?? 100000;
        if (typeof iterations !== "number" || iterations < 10000) {
            throw new Error("options.iterations must be a number >= 10000.");
        }
        this.password = password;
        this.iterations = iterations;
        this.keyLen = 32;
        this.digest = 'sha256';
    }
    deriveKey(salt) {
        const usedSalt = salt ?? crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(this.password, usedSalt, this.iterations, this.keyLen, this.digest);
        return { key, salt: usedSalt };
    }
    aesGcmEncrypt(plaintext, key) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { encrypted, iv, tag };
    }
    aesGcmDecrypt(encrypted, key, iv, tag) {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }
    /**
     * Encrypts a string using two AES-256-GCM layers.
     * @param content UTF-8 string (e.g. JSON, text) to encrypt.
     * @returns Encrypted base64 string.
     */
    encrypt(content) {
        const { key: key1, salt: salt1 } = this.deriveKey();
        const { encrypted: encrypted1, iv: iv1, tag: tag1 } = this.aesGcmEncrypt(content, key1);
        const { key: key2, salt: salt2 } = this.deriveKey();
        const innerEncoded = encrypted1.toString('base64');
        const { encrypted: encrypted2, iv: iv2, tag: tag2 } = this.aesGcmEncrypt(innerEncoded, key2);
        const combined = Buffer.concat([
            salt1, iv1, tag1,
            salt2, iv2, tag2,
            encrypted2
        ]);
        return combined.toString('base64');
    }
    /**
     * Decrypts an encrypted base64 string produced by `.encrypt`.
     * @param text Encrypted base64 string.
     * @returns Decrypted UTF-8 string.
     */
    decrypt(text) {
        const data = Buffer.from(text, 'base64');
        const salt1 = data.subarray(0, 16);
        const iv1 = data.subarray(16, 28);
        const tag1 = data.subarray(28, 44);
        const salt2 = data.subarray(44, 60);
        const iv2 = data.subarray(60, 72);
        const tag2 = data.subarray(72, 88);
        const encrypted2 = data.subarray(88);
        const key1 = this.deriveKey(salt1).key;
        const key2 = this.deriveKey(salt2).key;
        const decrypted1 = this.aesGcmDecrypt(encrypted2, key2, iv2, tag2);
        const encrypted1 = Buffer.from(decrypted1.toString('utf8'), 'base64');
        const plaintext = this.aesGcmDecrypt(encrypted1, key1, iv1, tag1);
        return plaintext.toString('utf8');
    }
}
