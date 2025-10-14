import crypto from "crypto";
import { Transform, type TransformCallback } from "stream";

/**
 * Options for creating an Encryptor instance.
 */
export type EncryptorOptions = {
	/**
	 * Amount of iterations for PBKDF2. Higher value = more CPU usage.
	 */
	iterations?: number;
	/**
	 * Optional pepper to combine with password for extra security. Not secret, but should be unique.
	 */
	pepper?: string;
	/**
	 * Suppress warnings.
	 */
	silent?: boolean;
	/**
	 * Enable streaming mode for large input/output. In streaming mode, data is processed in chunks and no random padding is added.
	 */
	stream?: boolean;
};

/**
 * AES-256-GCM encryption using PBKDF2 key derivation.
 * Supports both normal and streaming (chunked) encryption/decryption.
 */
export default class Encryptor {
	private password: string;
	private pepper?: string;
	private iterations: number;
	private keyLen: number;
	private digest: string;
	private encoding: BufferEncoding;
	private VERSION: number;
	private streamMode: boolean;

	/**
	 * Creates an Encryptor instance.
	 * @param password The password to use for encryption and decryption.
	 * @param options Optional configuration.
	 */
	public constructor(password: string, options?: EncryptorOptions) {
		if (password.length < 12) {
			if (!options?.silent) {
				console.warn(
					"[@kyvrixon/Encryptor]: ValidationWarn: Password should be at least 12 characters and a string.",
				);
			}
		}

		if (options?.iterations && options.iterations < 10000) {
			console.warn(
				"[@kyvrixon/Encryptor]: ValidatonWarn: 'options.iterations' must be a number >= 10000 for strong security",
			);
		}

		if (options?.pepper && typeof options.pepper !== "string") {
			throw new Error("Pepper must be a string if provided");
		}

		this.password = password;
		this.pepper = options?.pepper;
		this.iterations = options?.iterations || 50_000;
		this.keyLen = 32;
		this.digest = "sha512";
		this.encoding = "base64url";
		this.VERSION = 1;
		this.streamMode = !!options?.stream;
	}

	/**
	 * Creates a transform stream for chunked streaming encryption.
	 * Each chunk is encrypted and authenticated independently.
	 *
	 * No random padding is added in streaming mode. Chunk sizes are visible in output.
	 *
	 * @example
	 * const encryptor = new Encryptor('password', { stream: true });
	 * const encStream = await encryptor.createEncryptStream();
	 * inputStream.pipe(encStream).pipe(outputStream);
	 */
	public async createEncryptStream(): Promise<Transform> {
		if (!this.streamMode) {
			throw new Error("Streaming mode is not enabled in options");
		}

		return new Transform({
			transform: async (chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) => {
				try {
					const salt = crypto.randomBytes(16);
					const iv = crypto.randomBytes(12);
					const key = await this.deriveKey(salt);
					const header = Buffer.concat([Buffer.from([this.VERSION]), crypto.randomBytes(3)]);
					const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
					const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
					const tag = cipher.getAuthTag();
					const payload = Buffer.concat([header, salt, iv, tag, encrypted]);
					const hmac = crypto.createHmac(this.digest, key).update(payload).digest();
					const len = Buffer.alloc(4);

					len.writeUInt32BE(payload.length + hmac.length, 0);
					callback(null, Buffer.concat([len, payload, hmac]));
				} catch (err) {
					if (err instanceof Error) {
						callback(err as Error);
					}
				}
			},
		});
	}

	/**
	 * Creates a transform stream for chunked streaming decryption.
	 * Each chunk is decrypted and authenticated independently.
	 *
	 * @example
	 * const decryptor = new Encryptor('password', { stream: true });
	 * const decStream = await decryptor.createDecryptStream();
	 * encryptedStream.pipe(decStream).pipe(outputStream);
	 */
	public async createDecryptStream(): Promise<Transform> {
		if (!this.streamMode) {
			throw new Error("Streaming mode is not enabled in options");
		}

		let buffered: Buffer = Buffer.alloc(0);
		return new Transform({
			transform: async (chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) => {
				buffered = Buffer.concat([buffered, chunk]);
				const outputChunks: Buffer[] = [];
				let offset = 0;
				while (buffered.length - offset >= 4) {
					const chunkLen = buffered.readUInt32BE(offset);

					if (buffered.length - offset < 4 + chunkLen) {
						break;
					}

					const chunkStart = offset + 4;
					const chunkEnd = chunkStart + chunkLen;
					const chunkBuf = buffered.subarray(chunkStart, chunkEnd);
					const metaLen = 4 + 16 + 12 + 16;

					if (chunkBuf.length < metaLen + 32) {
						callback(new Error("Encrypted chunk too short"));
						return;
					}

					const salt = chunkBuf.subarray(4, 20);
					const iv = chunkBuf.subarray(20, 32);
					const tag = chunkBuf.subarray(32, 48);
					const hmac = chunkBuf.subarray(chunkBuf.length - 32);
					const encrypted = chunkBuf.subarray(48, chunkBuf.length - 32);
					const key = await this.deriveKey(salt);
					const payload = chunkBuf.subarray(0, chunkBuf.length - 32);
					const expectedHmac = crypto.createHmac("sha256", key).update(payload).digest();

					if (!crypto.timingSafeEqual(hmac, expectedHmac)) {
						callback(new Error("Integrity check failed: HMAC does not match"));
						return;
					}
					
					const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
					decipher.setAuthTag(tag);
					const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
					outputChunks.push(decrypted);
					offset = chunkEnd;
				}
				callback(null, Buffer.concat(outputChunks));
				buffered = buffered.subarray(offset);
			},
		});
	}

	/**
	 * Derives a key from password, optional pepper, and salt using PBKDF2.
	 *
	 * @param salt Salt value.
	 */
	private deriveKey(salt: Buffer): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			let secret = this.password;
			if (this.pepper) {
				secret += this.pepper;
			}
			crypto.pbkdf2(secret, salt, this.iterations, this.keyLen, this.digest, (err, key) => {
				if (err) {
					reject(new Error("Key derivation failed: " + err.message));
				} else {
					resolve(key);
				}
			});
		});
	}

	/**
	 * Encrypts a string using AES-256-GCM.
	 * Adds random padding to obfuscate plaintext length.
	 *
	 * @param plaintext The string to encrypt.
	 * @throws If input is invalid or encryption fails.
	 */
	public async encrypt(plaintext: string): Promise<string> {
		if (typeof plaintext !== "string" || plaintext.length === 0) {
			throw new Error("Plaintext must be a non-empty string");
		}

		const salt = crypto.randomBytes(16);
		const iv = crypto.randomBytes(12);
		const key = await this.deriveKey(salt);
		const padding = crypto.randomBytes(Math.floor(Math.random() * 16) + 1);
		const padded = Buffer.concat([
			Buffer.from(plaintext, "utf8"),
			padding,
			Buffer.from([padding.length]),
		]);

		const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
		let encrypted, tag: Buffer;
		try {
			encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
			tag = cipher.getAuthTag();
		} catch (err) {
			throw new Error("Encryption failed: " + (err instanceof Error ? err.message : String(err)));
		}

		const header = Buffer.concat([Buffer.from([this.VERSION]), crypto.randomBytes(3)]);
		const payload = Buffer.concat([header, salt, iv, tag, encrypted]);
		const hmac = crypto.createHmac("sha256", key).update(payload).digest();
		const final = Buffer.concat([payload, hmac]);

		return final.toString(this.encoding);
	}

	/**
	 * Decrypts a string using AES-256-GCM.
	 * Removes random padding and verifies integrity.
	 *
	 * @param encoded The encrypted string (base64url encoded).
	 * @throws If input is invalid, integrity check fails, or decryption fails.
	 */
	public async decrypt(encoded: string): Promise<string> {
		if (this.streamMode) {
			const buffer = Buffer.from(encoded, this.encoding);
			const version = buffer[0];

			if (version !== this.VERSION) {
				throw new Error(`Unsupported Encryptor version: ${version}`);
			}	
			if (buffer.length < 48 + 32) {
				throw new Error("Encoded input too short");
			}

			const payload = buffer.subarray(0, buffer.length - 32);
			const hmac = buffer.subarray(buffer.length - 32);
			const salt = payload.subarray(4, 20);
			const iv = payload.subarray(20, 32);
			const tag = payload.subarray(32, 48);
			const encrypted = payload.subarray(48);
			const key = await this.deriveKey(salt);
			const expectedHmac = crypto.createHmac("sha256", key).update(payload).digest();

			if (!crypto.timingSafeEqual(hmac, expectedHmac)) {
				throw new Error("Integrity check failed: HMAC does not match");
			}

			const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
			decipher.setAuthTag(tag);

			let padded: Buffer;
			try {
				padded = Buffer.concat([decipher.update(encrypted), decipher.final()]);
			} catch (err) {
				throw new Error("Decryption failed: " + (err instanceof Error ? err.message : String(err)));
			}
			const padLen = padded[padded.length - 1];
			if (!padLen || padLen < 1 || padLen > 16) {
				throw new Error("Invalid padding length detected");
			}
			const clean = padded.subarray(0, padded.length - padLen - 1);
			return clean.toString("utf8");
		} else {
			if (typeof encoded !== "string" || encoded.length === 0) {
				throw new Error("Encoded input must be a non-empty string");
			}
			let raw: Buffer;
			try {
				raw = Buffer.from(encoded, this.encoding);
			} catch (err) {
				throw new Error("Decoding failed: " + (err instanceof Error ? err.message : String(err)));
			}
			const version = raw[0];
			if (version !== this.VERSION) {
				throw new Error(`Unsupported Encryptor version: ${version}`);
			}
			if (raw.length < 48 + 32) {
				throw new Error("Encoded input too short");
			}

			const payload = raw.subarray(0, raw.length - 32);
			const hmac = raw.subarray(raw.length - 32);
			const salt = payload.subarray(4, 20);
			const iv = payload.subarray(20, 32);
			const tag = payload.subarray(32, 48);
			const encrypted = payload.subarray(48);
			const key = await this.deriveKey(salt);

			const expectedHmac = crypto.createHmac("sha256", key).update(payload).digest();
			if (!crypto.timingSafeEqual(hmac, expectedHmac)) {
				throw new Error("Integrity check failed: HMAC does not match");
			}

			const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
			decipher.setAuthTag(tag);

			let padded: Buffer;
			try {
				padded = Buffer.concat([decipher.update(encrypted), decipher.final()]);
			} catch (err) {
				throw new Error("Decryption failed: " + (err instanceof Error ? err.message : String(err)));
			}

			const padLen = padded[padded.length - 1];
			if (!padLen || padLen < 1 || padLen > 16) {
				throw new Error("Invalid padding length detected");
			}

			const clean = padded.subarray(0, padded.length - padLen - 1);
			return clean.toString("utf8");
		}
	}
}
