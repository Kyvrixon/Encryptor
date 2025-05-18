# @kyvrixon/encryptor

AES-256-GCM string encryption using PBKDF2 key derivation for Node.js.

## 📦 Installation

```bash
npm install @kyvrixon/encryptor@latest
```

## 🛠️ Usage

```ts
import Encryptor from '@kyvrixon/encryptor';

const password = 'supersecret';
const encryptor = new Encryptor(password);

const secretMessage = 'This is a secret!';
const encrypted = encryptor.encrypt(secretMessage);

console.log('Encrypted:', encrypted);

const decrypted = encryptor.decrypt(encrypted);
console.log('Decrypted:', decrypted); // This is a secret!
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

| Key | Type | Description | Default |
| -- | -- | -- | -- |
| `iterations` | `number` | Amount of iterations for PBKDF2. Higher value = more CPU usage | `100000` | 
