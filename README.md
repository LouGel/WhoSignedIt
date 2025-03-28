# Phantom Signer

A command-line tool for anonymous group signatures using Ethereum keys.

## Features

- Sign messages with your Ethereum private key using Alloy
- Generate proofs that you are part of a trusted group without revealing your identity
- Verify signatures and proofs
- Extensible architecture for future support of other blockchains like Solana

## Usage

### Sign a message

```bash
cargo run -- sign --message "Hello, world!" --private-key YOUR_PRIVATE_KEY_HEX --group group.txt
```

### Verify a signature

```bash
cargo run -- verify --message "Hello, world!" --signature signature.json --group group.txt
```

## Group File Format

The group file is a simple text file with one Ethereum address per line in hex format (with or without 0x prefix).

Example:

```
# Group members
0x742d35Cc6634C0532925a3b844Bc454e4438f44e
0x2e41f5cd1ea3809098731159c50297f3d21976993
```

## Error Handling

The tool uses `thiserror` for defining error types.

## Extending to Other Blockchains

The architecture is designed to be extensible. To add support for other blockchains:

1. Create a new module for the blockchain's key handling
2. Implement the necessary signature and verification logic
3. Update the CLI to accept the new key type

The core proof and group functionality can remain largely unchanged.
