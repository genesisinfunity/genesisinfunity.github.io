# Genesis Web App

Static GitHub Pages site for the Genesis Telegram menu button.

Current tool:

- Encryptor

Clipboard payload format:

- `[genesis-enc-v1] [RSA-OAEP-256+A256GCM] string:<encrypted-string>`
- `genesis-enc-v1` is the bridge/version tag
- `RSA-OAEP-256+A256GCM` is the actual encryption method label placed before `string:`

The page performs client-side hybrid encryption:

- RSA-OAEP-256 for wrapping a random AES key
- AES-256-GCM for the secret payload

The corresponding Genesis private key is kept only on the Genesis host under `/home/genesis/secrets/`.
