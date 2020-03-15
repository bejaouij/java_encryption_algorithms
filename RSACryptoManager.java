package helper.encryption;

import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RSACryptoManager extends CryptoManager {
    public RSACryptoManager() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance(RSA_ENCRYPT_METHOD);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm '" + DES_ENCRYPT_METHOD + "' does not exist.");
            e.printStackTrace();
        }
        keyGen.initialize(RSA_KEY_LENGTH);
        KeyPair keypair = keyGen.genKeyPair();
        asymmetricPrivateKey = keypair.getPrivate();
        asymmetricPublicKey = keypair.getPublic();
    }

    @Override
    public byte[] encrypt(byte[] clearMessage) {
        return encryption(clearMessage, ENCRYPT_MODE, RSA_ENCRYPT_METHOD, asymmetricPublicKey);
    }

    @Override
    public byte[] decrypt(byte[] encryptedMessage) {
        return encryption(encryptedMessage, DECRYPT_MODE, RSA_ENCRYPT_METHOD, asymmetricPrivateKey);
    }

    @Override
    public Key parseBytesToKey(byte[] keyContent) {
        KeyFactory keyFactory = null;

        try {
            keyFactory = KeyFactory.getInstance(RSA_ENCRYPT_METHOD);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(asymmetricPublicKey.getEncoded());

        try {
            return keyFactory.generatePublic(encodedKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Encrypt a given message with a specified key
     *
     * @param clearMessage : the message to encrypt
     * @param encryptionKey : the key used to encrypt the message
     * @return the encrypted message
     */
    public byte[] encrypt(byte[] clearMessage, Key encryptionKey) {
        return encryption(clearMessage, ENCRYPT_MODE, RSA_ENCRYPT_METHOD, encryptionKey);
    }
}
