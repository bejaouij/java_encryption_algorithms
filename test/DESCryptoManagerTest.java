package helper.encryption.test;

import helper.encryption.CryptoManager;
import helper.encryption.CryptoManagerFactory;

import static org.junit.jupiter.api.Assertions.*;

class DESCryptoManagerTest {
    @org.junit.jupiter.api.Test
    void encryption() {
        CryptoManager desCryptoManger = CryptoManagerFactory.getDESCryptoManager();

        String clearMessageString = "clear";

        byte[] encryptedMessage = desCryptoManger.encrypt(clearMessageString.getBytes());
        byte[] clearMessage = desCryptoManger.decrypt(encryptedMessage);

        assertEquals(clearMessageString, new String(clearMessage), "Clear message is not the same after encryption and decryption process.");
    }

    @org.junit.jupiter.api.Test
    void encryptionWithNotTheSameMessage() {
        CryptoManager desCryptoManger = CryptoManagerFactory.getDESCryptoManager();

        String clearMessageString = "clear";
        String wrongMessageString = "wrong";

        byte[] encryptedMessage = desCryptoManger.encrypt(wrongMessageString.getBytes());
        byte[] clearMessage = desCryptoManger.decrypt(encryptedMessage);

        assertNotEquals(clearMessageString, new String(clearMessage), "Clear is the same after encryption and decryption process with a wrong message.");
    }
}