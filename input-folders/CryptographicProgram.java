import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.jcajce.provider.asymmetric.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.jcajce.spec.FalconKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKEMGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class CryptographicProgram {

    static {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            // Generate RSA Key Pair
            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
            rsaGen.initialize(2048);
            KeyPair rsaKeyPair = rsaGen.generateKeyPair();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

            System.out.println("RSA Private Key: " + rsaPrivateKey);
            System.out.println("RSA Public Key: " + rsaPublicKey);

            // Generate DH Key Pair
            KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
            dhGen.initialize(2048);
            KeyPair dhKeyPair = dhGen.generateKeyPair();
            DHPrivateKey dhPrivateKey = (DHPrivateKey) dhKeyPair.getPrivate();
            DHPublicKey dhPublicKey = (DHPublicKey) dhKeyPair.getPublic();

            System.out.println("DH Private Key: " + dhPrivateKey);
            System.out.println("DH Public Key: " + dhPublicKey);

            // Generate EC Key Pair
            KeyPairGenerator ecGen = KeyPairGenerator.getInstance("ECDSA");
            ecGen.initialize(256);
            KeyPair ecKeyPair = ecGen.generateKeyPair();
            ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(ecKeyPair.getPrivate().getEncoded(), null);
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecKeyPair.getPublic().getEncoded(), null);

            System.out.println("EC Private Key Spec: " + ecPrivateKeySpec);
            System.out.println("EC Public Key Spec: " + ecPublicKeySpec);

            // Sign Data with RSA
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(rsaPrivateKey);
            String data = "Sample data for signing";
            signature.update(data.getBytes());
            byte[] sigBytes = signature.sign();

            System.out.println("RSA Signature: " + bytesToHex(sigBytes));

            // Dilithium Key Pair (PQC)
            DilithiumKeyPairGenerator dilithiumGen = new DilithiumKeyPairGenerator();
            dilithiumGen.initialize(null, null);
            KeyPair dilithiumKeyPair = dilithiumGen.generateKeyPair();

            System.out.println("Dilithium Private Key: " + dilithiumKeyPair.getPrivate());
            System.out.println("Dilithium Public Key: " + dilithiumKeyPair.getPublic());

            // Falcon Key Parameters (PQC)
            FalconKeyParameters falconKeyParams = new FalconKeyParameters();
            System.out.println("Falcon Key Parameters: " + falconKeyParams);

            // LMS Key Pair (PQC)
            LMSKeyPairGenerator lmsGen = new LMSKeyPairGenerator();
            lmsGen.initialize(null, null);
            KeyPair lmsKeyPair = lmsGen.generateKeyPair();

            System.out.println("LMS Private Key: " + lmsKeyPair.getPrivate());
            System.out.println("LMS Public Key: " + lmsKeyPair.getPublic());

            // NTRU KEM Generator (PQC)
            NTRUKEMGenerator ntruGen = new NTRUKEMGenerator();
            System.out.println("NTRU KEM Generator: " + ntruGen);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Utility method to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}

