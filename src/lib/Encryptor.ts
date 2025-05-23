import crypto from 'node:crypto';

type EncryptorOptions = {
    /**
     * Number of times to repeat the key derivation process.
     * Use at least 250,000 for better security (see [OWASP guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)).
     * Fewer repetitions make it easier for attackers to guess the password.
     * 
     * If your password is very strong (e.g., a combination of unique identifiers), you might use fewer repetitions.
     * Adjust based on your security needs.
     */
    iterations: number;
}

/**
 * AES-256-GCM string encryption using PBKDF2 key derivation with multi method encoding.
 */
export default class Encryptor {
    private password: string;
    private iterations: number;
    private keyLen: number;
    private digest: string;

    /**
     * Creates an instance of the Encryptor class.
     * @param password The password to use for encryption and decryption.
     */
    public constructor(password: string, options: EncryptorOptions) {
        if (typeof password !== "string" || password.length === 0) {
            throw new Error("Password must be a non-empty string");
        }

        if (!("iterations" in options)) {
            throw new Error("{ iterations: number; } must be provided.")
        };

        if (typeof options.iterations !== "number" || options.iterations < 1) {
            throw new Error("options.iterations must be a positive number");
        };

        if (password.length <= 10) {
            console.warn('\x1b[90m[@kyvrixon/Encryptor]\x1b[0m \x1b[33mInsecure password used, consider using a longer password.\x1b[0m');
        };

        this.password = password;
        this.iterations = options.iterations;
        this.keyLen = 32;
        this.digest = 'sha512';
    }

    private deriveKey(salt: Buffer): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(this.password, salt, this.iterations, this.keyLen, this.digest, (err, derivedKey) => {
                if (err) return reject(err);
                resolve(derivedKey);
            });
        });
    }

    public async encrypt(content: string): Promise<string> {
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12);
        const key = await this.deriveKey(salt);

        const padding = crypto.randomBytes(Math.floor(Math.random() * 16) + 1);
        const paddedContent = Buffer.concat([
            Buffer.from(content, 'utf8'),
            padding,
            Buffer.from([padding.length])
        ]);

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(paddedContent), cipher.final()]);
        const tag = cipher.getAuthTag();
        const header = crypto.randomBytes(4);

        const payload = Buffer.concat([
            header,
            salt,
            iv,
            tag,
            encrypted
        ]);

        return payload.toString('base64url');
    }

    public async decrypt(text: string): Promise<string> {
        try {
            const raw = Buffer.from(text, 'base64url');
            const salt = raw.subarray(4, 20);
            const iv = raw.subarray(20, 32);
            const tag = raw.subarray(32, 48);
            const encrypted = raw.subarray(48);

            const key = await this.deriveKey(salt);
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(tag);

            const padded = Buffer.concat([decipher.update(encrypted), decipher.final()]);
            const padLen = padded[padded.length - 1];
            const clean = padded.subarray(0, padded.length - padLen - 1);

            return clean.toString('utf8');
        } catch (err) {
            throw err;
        }
    }
}
