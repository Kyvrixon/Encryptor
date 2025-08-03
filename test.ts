
import Encryptor from './src/lib/Encryptor';

const testObj = {
    name: "Test User",
    age: 30,
    email: "test.user@example.com",
    address: {
        street: "123 Main St",
        city: "Metropolis",
        zip: "12345",
        country: "Neverland"
    },
    hobbies: ["reading", "coding", "gaming", "traveling"],
    isActive: true,
    scores: [98, 87, 92, 100, 76],
    preferences: {
        theme: "dark",
        notifications: {
            email: true,
            sms: false,
            push: true
        }
    },
    friends: [
        { name: "Alice", age: 28 },
        { name: "Bob", age: 32 },
        { name: "Charlie", age: 25 }
    ],
    metadata: {
        created: new Date().toISOString(),
        tags: ["test", "sample", "object"]
    }
};

async function testNormalEncryptDecrypt() {
    const encryptor = new Encryptor("HelloWorld!123$", { silent: true });
    const start = Date.now();
    const encrypted = await encryptor.encrypt(JSON.stringify(testObj));
    const encTime = Date.now() - start;
    const decStart = Date.now();
    const decrypted = await encryptor.decrypt(encrypted);
    const decTime = Date.now() - decStart;
    console.log("--- Normal Encrypt/Decrypt ---");
    console.log("Encrypted (base64url, first 100 chars):", encrypted.slice(0, 100) + (encrypted.length > 100 ? '...' : ''));
    console.log("Decrypted:", decrypted);
    console.log("Encrypt time:", encTime, "ms");
    console.log("Decrypt time:", decTime, "ms");
    console.log("Match:", decrypted === JSON.stringify(testObj));
}

async function testStreamingEncryptDecrypt() {
    const encryptor = new Encryptor("HelloWorld!123$", { silent: true, stream: true });
    const start = Date.now();
    // Streaming encrypt
    const encryptStream = await encryptor.createEncryptStream();
    const inputBuffer = Buffer.from(JSON.stringify(testObj), 'utf8');
    const chunkSize = 4096; // Increased chunk size for better performance
    let encryptedChunks: Buffer[] = [];
    encryptStream.on('data', chunk => encryptedChunks.push(chunk));
    encryptStream.on('end', async () => {
        const encryptedBuffer = Buffer.concat(encryptedChunks);
        const encTime = Date.now() - start;
        // Streaming decrypt
        const decStart = Date.now();
        const decryptStream = await encryptor.createDecryptStream();
        let decryptedChunks: Buffer[] = [];
        decryptStream.on('data', chunk => decryptedChunks.push(chunk));
        decryptStream.on('end', () => {
            const decryptedBuffer = Buffer.concat(decryptedChunks);
            const decTime = Date.now() - decStart;
            console.log("--- Streaming Encrypt/Decrypt ---");
            console.log("Encrypted (base64url, first 100 chars):", encryptedBuffer.toString('base64url').slice(0, 100) + (encryptedBuffer.length > 100 ? '...' : ''));
            console.log("Decrypted:", decryptedBuffer.toString('utf8'));
            console.log("Encrypt time:", encTime, "ms");
            console.log("Decrypt time:", decTime, "ms");
            console.log("Match:", decryptedBuffer.toString('utf8') === JSON.stringify(testObj));
        });
        decryptStream.end(encryptedBuffer);
    });
    for (let i = 0; i < inputBuffer.length; i += chunkSize) {
        encryptStream.write(inputBuffer.subarray(i, i + chunkSize));
    }
    encryptStream.end();
}

(async () => {
    await testNormalEncryptDecrypt();
    await testStreamingEncryptDecrypt();
})();