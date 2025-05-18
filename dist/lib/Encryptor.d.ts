/**
 * Encryptor for AES-256-GCM with double-layer encryption and PBKDF2 key derivation.
 */
export default class Encryptor {
    private password;
    private iterations;
    private keyLen;
    private digest;
    /**
     * Initializes a new instance of the Encryptor class.
     * @param password The encryption/decryption password. Must be at least 5 characters.
     * @param options Optional config: `iterations` for PBKDF2. Minimum 10,000.
     */
    constructor(password: string, options?: {
        iterations?: number;
    });
    private deriveKey;
    private aesGcmEncrypt;
    private aesGcmDecrypt;
    /**
     * Encrypts a string using two AES-256-GCM layers.
     * @param content UTF-8 string (e.g. JSON, text) to encrypt.
     * @returns Encrypted base64 string.
     */
    encrypt(content: string): string;
    /**
     * Decrypts an encrypted base64 string produced by `.encrypt`.
     * @param text Encrypted base64 string.
     * @returns Decrypted UTF-8 string.
     */
    decrypt(text: string): string;
}
