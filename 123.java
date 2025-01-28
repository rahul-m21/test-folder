import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DilithiumKeyPairGenerator;
import org.bouncycastle.crypto.generators.KyberKeyPairGenerator;
import org.bouncycastle.crypto.generators.SPHINCS256KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class CryptoDemo {
    public static void main(String[] args) {
        try {
            SecureRandom random = new SecureRandom();

            // Dilithium Key Pair Generation
            System.out.println("Generating Dilithium Key Pair...");
            DilithiumKeyPairGenerator dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
            dilithiumKeyPairGenerator.init(new DilithiumKeyGenerationParameters(random, 3));
            AsymmetricCipherKeyPair dilithiumKeyPair = dilithiumKeyPairGenerator.generateKeyPair();
            System.out.println("Dilithium Public Key: " + dilithiumKeyPair.getPublic());

            // Kyber Key Pair Generation
            System.out.println("\nGenerating Kyber Key Pair...");
            KyberKeyPairGenerator kyberKeyPairGenerator = new KyberKeyPairGenerator();
            kyberKeyPairGenerator.init(new KyberKeyGenerationParameters(random, 1024));
            AsymmetricCipherKeyPair kyberKeyPair = kyberKeyPairGenerator.generateKeyPair();
            System.out.println("Kyber Public Key: " + kyberKeyPair.getPublic());

            // SPHINCS+ Key Pair Generation
            System.out.println("\nGenerating SPHINCS+ Key Pair...");
            SPHINCS256KeyPairGenerator sphincsKeyPairGenerator = new SPHINCS256KeyPairGenerator();
            sphincsKeyPairGenerator.init(new SPHINCS256KeyGenerationParameters(random));
            AsymmetricCipherKeyPair sphincsKeyPair = sphincsKeyPairGenerator.generateKeyPair();
            System.out.println("SPHINCS+ Public Key: " + sphincsKeyPair.getPublic());

            // RSA Key Pair Generation
            System.out.println("\nGenerating RSA Key Pair...");
            RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
            rsaKeyPairGenerator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 80));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();
            RSAKeyParameters rsaPublicKey = (RSAKeyParameters) rsaKeyPair.getPublic();
            System.out.println("RSA Public Key: " + rsaPublicKey);

            // Ed448 Key Pair Generation
            System.out.println("\nGenerating Ed448 Key Pair...");
            Ed448KeyPairGenerator ed448KeyPairGenerator = new Ed448KeyPairGenerator();
            ed448KeyPairGenerator.init(new Ed448KeyGenerationParameters(random));
            AsymmetricCipherKeyPair ed448KeyPair = ed448KeyPairGenerator.generateKeyPair();
            System.out.println("Ed448 Public Key: " + ed448KeyPair.getPublic());

            // EC Key Pair Generation
            System.out.println("\nGenerating EC Key Pair...");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1"); // Example curve
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

            BigInteger privateKeyValue = new BigInteger(ecSpec.getN().bitLength(), random);
            ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(privateKeyValue, ecSpec);

            ECPoint q = ecSpec.getG().multiply(privateKeyValue);
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(q, ecSpec);
            ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);

            System.out.println("EC Public Key: " + ecPublicKey.getQ());

            // SHA-1 Digest Example
            System.out.println("\nComputing SHA-1 Digest...");
            SHA1Digest sha1 = new SHA1Digest();
            byte[] message = "Hello, World!".getBytes();
            sha1.update(message, 0, message.length);


            // RSA Encryption Example
            System.out.println("\nRSA Encryption...");
            RSAEngine rsaEngine = new RSAEngine();
            rsaEngine.init(true, rsaPublicKey);
            byte[] encryptedData = rsaEngine.processBlock(message, 0, message.length);
            System.out.println("Encrypted Data: " + Arrays.toString(encryptedData));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

