# SEAL File Encryption Example (TypeScript)

This project demonstrates how to use [Microsoft SEAL](https://www.microsoft.com/en-us/research/project/microsoft-seal/) (via the [`node-seal`](https://github.com/morfix-io/node-seal) library) in TypeScript to encrypt the contents of a local file (`input.txt`) and output the encrypted data to `output.txt`.

## Features

- Reads plaintext from `input.txt`
- Encrypts the data using homomorphic encryption (BFV scheme)
- Outputs the encrypted data to `output.txt`

## Prerequisites

- Node.js (v14+ recommended)
- npm

## Setup

1. **Install dependencies:**

   ```sh
   npm install
   ```

2. **Build the project:**

   ```sh
   npx tsc
   ```

3. **Prepare your input file:**
   - Edit or create `input.txt` in the project root with the text you want to encrypt.

## Usage

Run the encryption script:

```sh
node dist/encrypt.js
```

- The encrypted output will be saved to `output.txt`.

## Project Structure

- `encrypt.ts` - Main TypeScript script for encryption
- `input.txt` - Input file to be encrypted
- `output.txt` - Encrypted output file
- `tsconfig.json` - TypeScript configuration
- `.gitignore` - Standard ignores

## Notes

- This example uses small encryption parameters for demonstration and is **not secure for production**.
- Only encryption is demonstrated. Decryption and further homomorphic operations are not included.
- For more information, see the [node-seal documentation](https://github.com/morfix-io/node-seal).

---
