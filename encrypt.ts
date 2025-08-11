// --- Allowlist Setup Imports ---
import { SuiClient } from '@mysten/sui.js/client';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { RawSigner } from '@mysten/sui.js/signer';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { bcs } from '@mysten/bcs';
import fs from 'fs';
import Seal from 'node-seal';

// --- Allowlist Setup Constants ---
const ALLOWLIST_PACKAGE_ID = '0xb5c84864a69cb0b495caf548fa2bf0d23f6b69b131fa987d6f896d069de64429';
const SUI_RPC_URL = 'https://fullnode.testnet.sui.io:443'; // Sui testnet RPC

// Replace with your actual keypairs
const ADMIN_PRIVATE_KEY = '<ADMIN_PRIVATE_KEY_BASE64>'; // Admin wallet (gas sponsor)
const USER_ADDRESS = '<USER_WALLET_ADDRESS>'; // Wallet to be added to allowlist

async function addToAllowlist() {
    console.log('1. Adding user to allowlist...');
    const adminKeypair = Ed25519Keypair.fromSecretKey(Buffer.from(ADMIN_PRIVATE_KEY, 'base64'));
    const suiClient = new SuiClient({ url: SUI_RPC_URL });
    const signer = new RawSigner(adminKeypair, suiClient);

    // Prepare the transaction to call the allowlist's add_user function
    const tx = new TransactionBlock();
    // The function signature may vary; check the package for exact call
    tx.moveCall({
        target: `${ALLOWLIST_PACKAGE_ID}::allowlist::add_user`,
        arguments: [
            tx.pure(USER_ADDRESS)
        ]
    });

    // Sponsor gas and send transaction
    const result = await signer.signAndExecuteTransactionBlock({ transactionBlock: tx });
    console.log('Allowlist transaction response:', result);
}

async function main() {
    // --- Allowlist Setup ---
    await addToAllowlist();

    // Initialize SEAL
    const seal = await Seal();

    // Set encryption parameters
    const schemeType = seal.SchemeType.bfv;
    const parms = seal.EncryptionParameters(schemeType);
    parms.setPolyModulusDegree(2048);
    parms.setCoeffModulus(seal.CoeffModulus.BFVDefault(2048));
    parms.setPlainModulus(seal.PlainModulus.Batching(2048, 20));

    const context = seal.Context(
        parms, // Encryption Parameters
        true,  // ExpandModChain
        seal.SecurityLevel.tc128
    );

    if (!context.parametersSet()) {
        throw new Error('Encryption parameters are not valid');
    }

    // Generate keys
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    // const secretKey = keyGenerator.secretKey(); // Not used for encryption

    // Create Encryptor, Encoder
    const encryptor = seal.Encryptor(context, publicKey);
    const encoder = seal.BatchEncoder(context);

    // Read input file
    const input = fs.readFileSync('input.txt', 'utf8');
    // Convert string to char codes and pad to poly modulus degree
    const inputCodes = Array.from(input).map(c => c.charCodeAt(0));
    while (inputCodes.length < encoder.slotCount) inputCodes.push(0);

    // Convert to BigInt for BigUint64Array
    const inputBigInts = inputCodes.map(n => BigInt(n));
    const inputBigUint64Array = BigUint64Array.from(inputBigInts);
    const plain = encoder.encode(inputBigUint64Array);
    if (!plain) {
        throw new Error('Encoding failed, plain is undefined');
    }
    const cipher = seal.CipherText();
    encryptor.encrypt(plain, cipher);

    // Serialize ciphertext to base64
    const cipherBase64 = cipher.save();

    // Write to output file
    fs.writeFileSync('output.txt', cipherBase64);

    console.log('Encryption complete. Output written to output.txt');
}

main().catch(console.error);
