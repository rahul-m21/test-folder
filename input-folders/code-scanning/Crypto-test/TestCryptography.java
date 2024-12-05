import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.spec.ECGenParameterSpec;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class TestCryptography {

    public static void main(String[] args) throws Exception {
        // Add the BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());

        // RSA Key Pair (non-PQC)
        generateRSAKeys();

        // ECDSA Key Pair (non-PQC)
        generateECDSAKeys();

        // XMSS Key Pair (PQC)
        generateXMSSKeys();

        // SHA-256 Digest (non-PQC)
        sha256Digest();

        // SHAKE-128 Digest (PQC)
        shake128Digest();
    }

    /**
     * Generate RSA Key Pair and print the keys.
     * RSA is a non-PQC algorithm.
     */
    private static void generateRSAKeys() throws Exception {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(
                new BigInteger("10001", 16), random, 2048, 12);

        generator.init(params);
        AsymmetricKeyParameter privateKey = generator.generateKeyPair().getPrivate();
        AsymmetricKeyParameter publicKey = generator.generateKeyPair().getPublic();

        System.out.println("=== RSA Key Pair (non-PQC) ===");
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    /**
     * Generate ECDSA Key Pair and print the keys.
     * ECDSA is a non-PQC algorithm.
     */
    private static void generateECDSAKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec, new SecureRandom());

        KeyPair keyPair = keyGen.generateKeyPair();

        System.out.println("=== ECDSA Key Pair (non-PQC) ===");
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    /**
     * Generate XMSS Key Pair and print the keys.
     * XMSS is a PQC algorithm.
     */
    private static void generateXMSSKeys() throws Exception {
        XMSSKeyPairGenerator xmssGen = new XMSSKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        XMSSKeyGenerationParameters params = new XMSSKeyGenerationParameters(
                new XMSSParameters(10, new SHA256Digest()), random);

        xmssGen.init(params);
        AsymmetricCipherKeyPair keyPair = xmssGen.generateKeyPair();
        XMSSPrivateKeyParameters privateKey = (XMSSPrivateKeyParameters) keyPair.getPrivate();
        XMSSPublicKeyParameters publicKey = (XMSSPublicKeyParameters) keyPair.getPublic();

        System.out.println("=== XMSS Key Pair (PQC) ===");
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    /**
     * Calculate SHA-256 Digest.
     * SHA-256 is a non-PQC algorithm.
     */
    private static void sha256Digest() {
        byte[] message = "Hello, World!".getBytes();
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(message, 0, message.length);

        byte[] digest = new byte[sha256.getDigestSize()];
        sha256.doFinal(digest, 0);

        System.out.println("=== SHA-256 Digest (non-PQC) ===");
        System.out.println("Digest: " + Base64.getEncoder().encodeToString(digest));
    }

    /**
     * Calculate SHAKE-128 Digest.
     * SHAKE-128 is a PQC algorithm.
     */
    private static void shake128Digest() {
        byte[] message = "Hello, Post-Quantum!".getBytes();
        SHAKEDigest shake128 = new SHAKEDigest(128);
        shake128.update(message, 0, message.length);

        byte[] digest = new byte[32]; // 256 bits of output
        shake128.doFinal(digest, 0, digest.length);

        System.out.println("=== SHAKE-128 Digest (PQC) ===");
        System.out.println("Digest: " + Base64.getEncoder().encodeToString(digest));
    }
}
