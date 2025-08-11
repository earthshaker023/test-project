import fs from 'fs';
import Seal from 'node-seal';

async function main() {
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
