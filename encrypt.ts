// --- Allowlist Setup Imports ---
import { SuiClient } from '@mysten/sui.js/client';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { bcs } from '@mysten/bcs';
import fs from 'fs';
import Seal from 'node-seal';

// --- Allowlist Setup Constants ---
const ALLOWLIST_PACKAGE_ID = '0xb5c84864a69cb0b495caf548fa2bf0d23f6b69b131fa987d6f896d069de64429';
const SUI_RPC_URL = 'https://fullnode.testnet.sui.io:443'; // Sui testnet RPC

// Replace with your actual keypairs
const ADMIN_PRIVATE_KEY = 'suiprivkey1qpjx9gjjr7j4vjv4s26fa9f4htpurey8xqt5wszkn7pgymumqnwqk62fzt5'; // Admin wallet (gas sponsor)
const USER_ADDRESS = '0x72a24df80ed713fd193e43efe860eb36f301ecef59566c03e7784b210b879a3a'; // Wallet to be added to allowlist

async function addToAllowlist() {
    console.log('1. Adding user to allowlist...');
    const secretKeyBytes = Buffer.from(ADMIN_PRIVATE_KEY, 'base64');
    if (secretKeyBytes.length !== 64) {
        throw new Error('ADMIN_PRIVATE_KEY must be a base64-encoded 64-byte Ed25519 secret key');
    }
    const adminKeypair = Ed25519Keypair.fromSecretKey(secretKeyBytes);
    const suiClient = new SuiClient({ url: SUI_RPC_URL });

    // Build the transaction block
    const tx = new TransactionBlock();
    tx.moveCall({
        target: `${ALLOWLIST_PACKAGE_ID}::allowlist::add_user`,
        arguments: [
            tx.pure(USER_ADDRESS, 'address')
        ]
    });

    // Sign and execute the transaction directly using the keypair and client
    const { bytes, signature } = await tx.sign({
        client: suiClient,
        signer: adminKeypair,
    });

    const result = await suiClient.executeTransactionBlock({
        transactionBlock: bytes,
        signature,
    });

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

    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    // const secretKey = keyGenerator.secretKey(); // Not used for encryption

    const encryptor = seal.Encryptor(context, publicKey);
    const encoder = seal.BatchEncoder(context);

    const input = fs.readFileSync('input.txt', 'utf8');
    const inputCodes = Array.from(input).map(c => c.charCodeAt(0));
    while (inputCodes.length < encoder.slotCount) inputCodes.push(0);

    const inputBigInts = inputCodes.map(n => BigInt(n));
    const inputBigUint64Array = BigUint64Array.from(inputBigInts);
    const plain = encoder.encode(inputBigUint64Array);
    if (!plain) {
        throw new Error('Encoding failed, plain is undefined');
    }
    const cipher = seal.CipherText();
    encryptor.encrypt(plain, cipher);

    const cipherBase64 = cipher.save();

    fs.writeFileSync('output.txt', cipherBase64);

    console.log('Encryption complete. Output written to output.txt');
}

main().catch(console.error);
