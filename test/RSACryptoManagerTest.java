package helper.encryption.test;

import helper.encryption.CryptoManager;
import helper.encryption.CryptoManagerFactory;

import java.security.Key;

import static org.junit.jupiter.api.Assertions.*;

class RSACryptoManagerTest {
    @org.junit.jupiter.api.Test
    void encryption() {
        CryptoManager rsaCryptoManger = CryptoManagerFactory.getRSACryptoManager();

        String clearMessageString = "clear";

        byte[] encryptedMessage = rsaCryptoManger.encrypt(clearMessageString.getBytes());
        byte[] clearMessage = rsaCryptoManger.decrypt(encryptedMessage);

        assertEquals(clearMessageString, new String(clearMessage), "Clear message is not the same after encryption and decryption process.");
    }

    @org.junit.jupiter.api.Test
    void encryptionWithNotTheSameMessage() {
        CryptoManager rsaCryptoManger = CryptoManagerFactory.getRSACryptoManager();

        String clearMessageString = "clear";
        String wrongMessageString = "wrong";

        byte[] encryptedMessage = rsaCryptoManger.encrypt(wrongMessageString.getBytes());
        byte[] clearMessage = rsaCryptoManger.decrypt(encryptedMessage);

        assertNotEquals(clearMessageString, new String(clearMessage), "Clear is the same after encryption and decryption process with a wrong message.");
    }

    @org.junit.jupiter.api.Test
    void parseBytesToKey() {
        CryptoManager rsaCryptoManger = CryptoManagerFactory.getRSACryptoManager();

        byte[] rsaKeyContent = rsaCryptoManger.getAsymmetricPublicKey().getEncoded();
        Key parsedKey = rsaCryptoManger.parseBytesToKey(rsaKeyContent);

        assertEquals(rsaCryptoManger.getAsymmetricPublicKey(), parsedKey, "Parsed key has been corrupt.");
    }
}