import crypto from 'node:crypto';

/**
 * AES-256-GCM string encryption using PBKDF2 key derivation for Node.js.
 */
export default class Encryptor {
    private password: string;
    private iterations: number;
    private keyLen: number;
    private digest: string;

    constructor(password: string, options?: { iterations?: number }) {
        if (typeof password !== "string") {
            throw new Error("Password must be a non-empty string");
        };

        const iterations = options?.iterations ?? 100_000;
        if (typeof iterations !== "number" || iterations < 10_000) {
            throw new Error("options.iterations must be a number equal or higher than 10000.");
        };

        if (password.length <= 5) {
            console.warn('\x1b[35m[@kyvrixon/Encryptor]\x1b[0m \x1b[33mInsecure password used. Consider using a longer password.\x1b[0m');
        }

        this.password = password;
        this.iterations = iterations;
        this.keyLen = 32;
        this.digest = 'sha512';
    }

    private deriveKey(salt?: Buffer): { key: Buffer; salt: Buffer } {
        const usedSalt = salt ?? crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(this.password, usedSalt, this.iterations, this.keyLen, this.digest);
        return { key, salt: usedSalt };
    }

    private aesGcmEncrypt(content: string, key: Buffer): { encrypted: Buffer; iv: Buffer; tag: Buffer } {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(content, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { encrypted, iv, tag };
    }

    private aesGcmDecrypt(encrypted: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Buffer {
        try {
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(tag);
            return Buffer.concat([decipher.update(encrypted), decipher.final()]);
        } catch (e) {
            throw e;
        }
    }


    /**
     * Encrypts a string using AES-256-GCM.
     * @param content UTF-8 string (e.g. JSON, text) to encrypt.
     * @returns Encrypted base64 string.
     */
    public encrypt(content: string): string {
        const { key, salt } = this.deriveKey();
        const { encrypted, iv, tag } = this.aesGcmEncrypt(content, key);

        const combined = Buffer.concat([
            salt,
            iv,
            tag,
            encrypted
        ]);

        return combined.toString('base64');
    }

    /**
     * Decrypts an encrypted base64 string produced by `.encrypt`.
     * @param text Encrypted base64 string.
     * @returns Decrypted UTF-8 string.
     */
    public decrypt(text: string): string {
        try {
            const data = Buffer.from(text, 'base64');

            const salt = data.subarray(0, 16);
            const iv = data.subarray(16, 28);
            const tag = data.subarray(28, 44);
            const encrypted = data.subarray(44);

            const key = this.deriveKey(salt).key;

            const plaintext = this.aesGcmDecrypt(encrypted, key, iv, tag);

            return plaintext.toString('utf8');
        } catch (err) {
            console.error('\x1b[31mDecryption failed: Incorrect key or corrupted data.\x1b[0m', (err as Error).message);
            return "";
        }
    }
}
