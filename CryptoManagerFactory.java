package helper.encryption;

public abstract class CryptoManagerFactory {
    public static CryptoManager getDESCryptoManager() {
        return new DESCryptoManager();
    }

    public static CryptoManager getRSACryptoManager() {
        return new RSACryptoManager();
    }
}
