package helper.encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class DESCryptoManager extends CryptoManager {
    public DESCryptoManager() {
        KeyGenerator keyGenerator = null;

        try {
            keyGenerator = KeyGenerator.getInstance(DES_ENCRYPT_METHOD);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm '" + DES_ENCRYPT_METHOD + "' does not exist.");
            e.printStackTrace();
        }

        keyGenerator.init(DES_KEY_LENGTH);
        symmetricEncryptionKey = keyGenerator.generateKey();
    }

    @Override
    public byte[] encrypt(byte[] clearMessage) {
        return encryption(clearMessage, ENCRYPT_MODE, DES_ENCRYPT_METHOD, symmetricEncryptionKey);
    }

    @Override
    public byte[] decrypt(byte[] encryptedMessage) {
        return encryption(encryptedMessage, DECRYPT_MODE, DES_ENCRYPT_METHOD, symmetricEncryptionKey);
    }

    @Override
    public Key parseBytesToKey(byte[] keyContent) {
        return new SecretKeySpec(keyContent, DES_ENCRYPT_METHOD);
    }
}