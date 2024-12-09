package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.sphincs.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

    public class KyberEncryptionDemo {

        static {
            // Add Bouncy Castle as a security provider
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        public static void main(String[] args) {
            try {
                System.out.println("Hybrid Cryptography: SPHINCS+ (PQC) + RSA");

                // Document to be signed and encrypted
                String document = "This is a highly sensitive document.";
                byte[] documentBytes = document.getBytes(StandardCharsets.UTF_8);

                // Step 1: Generate SPHINCS+ Key Pair for Signing (PQC)
                System.out.println("\nGenerating SPHINCS+ Key Pair for signing...");
                AsymmetricCipherKeyPair sphincsKeyPair = generateSphincsKeyPair();
                SPHINCSPrivateKeyParameters sphincsPrivateKey = (SPHINCSPrivateKeyParameters) sphincsKeyPair.getPrivate();
                SPHINCSPublicKeyParameters sphincsPublicKey = (SPHINCSPublicKeyParameters) sphincsKeyPair.getPublic();

                // Step 2: Sign the document using SPHINCS+
                System.out.println("\nSigning the document using SPHINCS+...");
                byte[] signature = pqcSphincsSignature(sphincsPrivateKey, documentBytes);
                System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

                // Step 3: Verify the signature using SPHINCS+
                System.out.println("\nVerifying the SPHINCS+ signature...");
                boolean isSignatureValid = pqcSphincsVerify(sphincsPublicKey, documentBytes, signature);
                System.out.println("Signature valid: " + isSignatureValid);

                // Step 4: Generate RSA Key Pair for Encryption (Non-PQC)
                System.out.println("\nGenerating RSA Key Pair for encryption...");
                KeyPair rsaKeyPair = generateRSAKeyPair();
                PublicKey rsaPublicKey = rsaKeyPair.getPublic();
                PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();

                // Step 5: Encrypt the signed document using RSA
                System.out.println("\nEncrypting the signed document using RSA...");
                byte[] encryptedDocument = encryptWithRSA(rsaPublicKey, documentBytes);
                System.out.println("Encrypted Document: " + Base64.getEncoder().encodeToString(encryptedDocument));

                // Step 6: Decrypt the signed document using RSA
                System.out.println("\nDecrypting the signed document using RSA...");
                byte[] decryptedDocument = decryptWithRSA(rsaPrivateKey, encryptedDocument);
                System.out.println("Decrypted Document: " + new String(decryptedDocument, StandardCharsets.UTF_8));

                // Final Step: Verify the signature on the decrypted document
                System.out.println("\nVerifying signature on decrypted document...");
                boolean isDecryptedSignatureValid = pqcSphincsVerify(sphincsPublicKey, decryptedDocument, signature);
                System.out.println("Signature on decrypted document valid: " + isDecryptedSignatureValid);

            } catch (Exception e) {
                System.err.println("An error occurred: " + e.getMessage());
                e.printStackTrace();
            }
        }

        // Utility: Generate SPHINCS+ Key Pair
        public static AsymmetricCipherKeyPair generateSphincsKeyPair() {
            SPHINCS256KeyPairGenerator generator = new SPHINCS256KeyPairGenerator();
            generator.init(new SPHINCS256KeyGenerationParameters(new SecureRandom(), new SHA3Digest(256)));
            return generator.generateKeyPair();
        }

        // Utility: Sign a message using SPHINCS+
        public static byte[] pqcSphincsSignature(SPHINCSPrivateKeyParameters privateKey, byte[] message) {
            MessageSigner signer = new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512));
            signer.init(true, privateKey);
            return signer.generateSignature(message);
        }

        // Utility: Verify a SPHINCS+ signature
        public static boolean pqcSphincsVerify(SPHINCSPublicKeyParameters publicKey, byte[] message, byte[] signature) {
            MessageSigner signer = new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512));
            signer.init(false, publicKey);
            return signer.verifySignature(message, signature);
        }

        // Utility: Generate RSA Key Pair
        public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048); // 2048-bit RSA keys
            return keyPairGen.generateKeyPair();
        }

        // Utility: Encrypt data using RSA
        public static byte[] encryptWithRSA(PublicKey publicKey, byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }

        // Utility: Decrypt data using RSA
        public static byte[] decryptWithRSA(PrivateKey privateKey, byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        }
    }

