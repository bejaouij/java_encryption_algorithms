package helper.encryption;

import java.security.*;

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
}
