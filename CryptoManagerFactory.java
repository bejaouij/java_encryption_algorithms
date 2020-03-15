package helper.encryption;

import java.security.Key;

public abstract class CryptoManagerFactory {
    public static CryptoManager getDESCryptoManager() {
        return new DESCryptoManager();
    }

    public static CryptoManager getDESCryptoManager(Key encryptionKey) {
        return new DESCryptoManager(encryptionKey);
    }

    public static CryptoManager getRSACryptoManager() {
        return new RSACryptoManager();
    }
}
