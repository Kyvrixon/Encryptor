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
        if (typeof iterations !== "number") {
            throw new Error("option.iterations must be a number");
        };

        if (iterations < 10_000) {
            console.warn('\x1b[90m[@kyvrixon/Encryptor]\x1b[0m \x1b[33mLow iteraction count. Consider using a higher value like 25000\x1b[0m');
        };

        if (password.length <= 5) {
            console.warn('\x1b[90m[@kyvrixon/Encryptor]\x1b[0m \x1b[33mInsecure password used. Consider using a longer password.\x1b[0m');
        }

        this.password = password;
        this.iterations = iterations;
        this.keyLen = 32;
        this.digest = 'sha512';
    }

    private deriveKey(salt?: Buffer): Promise<{ key: Buffer; salt: Buffer }> {
        if (salt) {
            return new Promise((resolve, reject) => {
                crypto.pbkdf2(this.password, salt, this.iterations, this.keyLen, this.digest, (err, derivedKey) => {
                    if (err) return reject(err);
                    resolve({ key: derivedKey, salt });
                });
            });
        } else {
            return new Promise((resolve, reject) => {
                crypto.randomBytes(16, (err, newSalt) => {
                    if (err) {
                        reject(err);
                    } else {
                        crypto.pbkdf2(this.password, newSalt, this.iterations, this.keyLen, this.digest, (err2, derivedKey) => {
                            if (err2) return reject(err2);
                            resolve({ key: derivedKey, salt: newSalt });
                        });
                    }
                });
            });
        }
    }

    private aesGcmEncrypt(content: string, key: Buffer): Promise<{ encrypted: Buffer; iv: Buffer; tag: Buffer }> {
        return new Promise((resolve, reject) => {
            crypto.randomBytes(12, (err, iv) => {
                if (err) {
                    reject(err);
                } else {
                    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
                    const encrypted = Buffer.concat([cipher.update(content, 'utf8'), cipher.final()]);
                    const tag = cipher.getAuthTag();
                    resolve({ encrypted, iv, tag });
                }
            });
        });
    }

    private aesGcmDecrypt(encrypted: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            try {
                const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
                decipher.setAuthTag(tag);
                resolve(Buffer.concat([decipher.update(encrypted), decipher.final()]));
            } catch (e) {
                reject(e);
            }
        });
    }


    /**
     * Encrypts a string using AES-256-GCM.
     * @param content UTF-8 string (e.g. JSON, text) to encrypt.
     * @returns Encrypted base64 string.
     */
    public async encrypt(content: string): Promise<string> {
        const { key, salt } = await this.deriveKey();
        const { encrypted, iv, tag } = await this.aesGcmEncrypt(content, key);

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
    public async decrypt(text: string): Promise<string> {
        try {
            const data = Buffer.from(text, 'base64');

            const salt = data.subarray(0, 16);
            const iv = data.subarray(16, 28);
            const tag = data.subarray(28, 44);
            const encrypted = data.subarray(44);

            const key = (await this.deriveKey(salt)).key;

            const plaintext = await this.aesGcmDecrypt(encrypted, key, iv, tag);

            return plaintext.toString('utf8');
        } catch (err) {
            console.error('\x1b[31mDecryption failed: Incorrect key or corrupted data.\x1b[0m', (err as Error).message);
            return "";
        }
    }
}

