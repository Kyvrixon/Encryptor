
# @kyvrixon/encryptor

Robust AES-256-GCM encryption and decryption for Javascript, supporting secure string and streaming (chunked) data with PBKDF2 key derivation and HMAC integrity. Designed for both small secrets and massive files, with memory-safe streaming API.

## 📦 Installation

> [!TIP] Works with most package managers not just `npm`!

```bash
npm install @kyvrixon/encryptor@latest
```

## 🛠️ Usage

### Normal (String) Encryption

```ts
import Encryptor from '@kyvrixon/encryptor';

(async () => {
    const password = 'supersecret';
    const encryptor = new Encryptor(password);

    const secretMessage = 'This is a secret!';
    const encrypted = await encryptor.encrypt(secretMessage);
    console.log('Encrypted:', encrypted);

    const decrypted = await encryptor.decrypt(encrypted);
    console.log('Decrypted:', decrypted); // This is a secret!
})();
```

### Streaming (Chunked) Encryption/Decryption

```ts
import Encryptor from '@kyvrixon/encryptor';
import { createReadStream, createWriteStream } from 'fs';

(async () => {
    const password = 'supersecret';
    // Enable streaming mode
    const encryptor = new Encryptor(password, { stream: true });

    // Encrypt a file in chunks
    const encStream = await encryptor.createEncryptStream();
    createReadStream('input.txt').pipe(encStream).pipe(createWriteStream('encrypted.bin'));

    // Decrypt a file in chunks
    const decStream = await encryptor.createDecryptStream();
    createReadStream('encrypted.bin').pipe(decStream).pipe(createWriteStream('output.txt'));

    // --- Streaming to an array (in-memory) ---
    const inputBuffer = Buffer.from('stream this data!', 'utf8');
    const encryptStream2 = await encryptor.createEncryptStream();
    let encryptedChunks: Buffer[] = [];
    encryptStream2.on('data', chunk => encryptedChunks.push(chunk));
    encryptStream2.on('end', async () => {
        const encryptedBuffer = Buffer.concat(encryptedChunks);
        // Decrypt back to array
        const decryptStream2 = await encryptor.createDecryptStream();
        let decryptedChunks: Buffer[] = [];
        decryptStream2.on('data', chunk => decryptedChunks.push(chunk));
        decryptStream2.on('end', () => {
            const decryptedBuffer = Buffer.concat(decryptedChunks);
            console.log('Decrypted (streamed to array):', decryptedBuffer.toString('utf8'));
        });
        decryptStream2.end(encryptedBuffer);
    });
    encryptStream2.end(inputBuffer);
})();
```

## ⚙️ Options

```ts
const encryptor = new Encryptor(
    password,
    {
        // Below options go here
    }
);
```

| Key         | Type      | Description                                                                                  | Default   |
|-------------|-----------|----------------------------------------------------------------------------------------------|-----------|
| `iterations`| `number`  | Amount of iterations for PBKDF2. Higher value = more CPU usage.                              | `50000`   |
| `pepper`    | `string`  | Optional pepper to combine with password for extra security. Not secret, but should be unique.| `undefined`|
| `silent`    | `boolean` | Suppress warnings.                                                                           | `false`   |
| `stream`    | `boolean` | Enable streaming mode for large input/output. In streaming mode, data is processed in chunks and no random padding is added. | `false` |

## 🔒 Security Notes

- Uses AES-256-GCM for authenticated encryption.
- PBKDF2 key derivation with SHA-512 and configurable iterations.
- HMAC-SHA256 for integrity/authentication.
- Streaming mode is memory safe and chunked, suitable for massive data/files.
- In streaming mode, chunk sizes are visible (no random padding).

## 📚 API

### `new Encryptor(password: string, options?: EncryptorOptions)`

Creates an Encryptor instance.

### `encrypt(plaintext: string): Promise<string>`

Encrypts a string and returns a base64url-encoded ciphertext.

### `decrypt(encoded: string): Promise<string>`

Decrypts a base64url-encoded ciphertext and returns the original string.

### `createEncryptStream(): Promise<Transform>`

Returns a Transform stream for chunked streaming encryption. Each chunk is encrypted and authenticated independently.

### `createDecryptStream(): Promise<Transform>`

Returns a Transform stream for chunked streaming decryption. Each chunk is decrypted and authenticated independently.
