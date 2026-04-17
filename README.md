# Genesis Web App

Static GitHub Pages site for the Genesis Telegram menu button.

Current tool:

- Encryptor

Clipboard payload format:

- `[RSA-OAEP-256+A256GCM] string:<encrypted-string>`
- the prefix names the encryption method, not the product/version tag

The page performs client-side hybrid encryption:

- RSA-OAEP-256 for wrapping a random AES key
- AES-256-GCM for the secret payload

The corresponding Genesis private key is kept only on the Genesis host under `/home/genesis/secrets/`.
