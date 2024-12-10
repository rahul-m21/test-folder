import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSAExample {

    public static void main(String[] args) {
        try {
            // Step 1: Generate RSA Key Pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(2048); // Specify the key size (2048 bits)
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println("Generated RSA Key Pair:");
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

            // Step 2: Encrypt a Message
            String plainText = "This is a secret message";
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = encryptCipher.doFinal(plainText.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            System.out.println("Encrypted Message: " + encryptedText);

            // Step 3: Decrypt the Message
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedText));
            String decryptedText = new String(decryptedBytes);

            System.out.println("Decrypted Message: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

