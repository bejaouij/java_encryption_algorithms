package helper.encryption;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public abstract class CryptoManager {
    public static int DECRYPT_MODE = Cipher.DECRYPT_MODE;
    public static int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
    public static String DES_ENCRYPT_METHOD = "DES";
    public static String RSA_ENCRYPT_METHOD = "RSA";

    protected static Integer DES_KEY_LENGTH = 56;
    protected static Integer RSA_KEY_LENGTH = 1024;
    protected Key symmetricEncryptionKey;
    protected Key asymmetricPublicKey;
    protected Key asymmetricPrivateKey;

    /**
     * Get the symmetric encryption key
     *
     * @return the symmetric encryption key
     */
    public Key getSymmetricEncryptionKey() {
        return symmetricEncryptionKey;
    }

    /**
     * Get the asymmetric public encryption key
     *
     * @return the asymmetric public encryption key
     */
    public Key getAsymmetricPublicKey() {
        return asymmetricPublicKey;
    }

    /**
     * Get the asymmetric private encryption key
     *
     * @return the asymmetric private encryption key
     */
    public Key getAsymmetricPrivateKey() {
        return asymmetricPrivateKey;
    }

    /**
     * Process an encryption on a provided message.
     *
     * @param message : the message to encrypt or decrypt
     * @param mode : ENCRYPT_MODE - encryption, DECRYPT_MODE - decryption
     * @param encryptionMethod : DES_ENCRYPT_METHOD - DES, RSA_ENCRYPT_METHOD - RSA
     * @param encryptionKey : key used for encryption process
     *
     * @return encrypted or decrypted message
     */
    protected byte[] encryption(byte[] message, int mode, String encryptionMethod, Key encryptionKey) {
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance(encryptionMethod);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.out.println("Algorithm '" + encryptionMethod + "' does not exist.");
            e.printStackTrace();
        }

        try {
            cipher.init(mode, encryptionKey);
        } catch (InvalidKeyException e) {
            System.out.println("Invalid provided key.");
            e.printStackTrace();
        }

        byte[] messageBytes = null;

        try {
            messageBytes = cipher.doFinal(message);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return messageBytes;
    }

    /**
     * Decrypt a given message
     *
     * @param encryptedMessage : the message to decrypt
     *
     * @return the decrypted message
     */
    public abstract byte[] decrypt(byte[] encryptedMessage);

    /**
     * Encrypt a given message
     *
     * @param clearMessage : the message to encrypt
     *
     * @return the encrypted message
     */
    public abstract byte[] encrypt(byte[] clearMessage);

    /**
     * Parse given bytes to a key
     *
     * @param keyContent : the key content
     * @return the parsed key
     */
    public abstract Key parseBytesToKey(byte[] keyContent);
}
