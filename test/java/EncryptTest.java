import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EncryptTest {
    @Test
    public void givenString_whenEncrypt_thenSuccess() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String input = "Bluecoder_01";
        SecretKey key = Main.generateKey(128);
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = Main.generateIv();
        String cipherText = Main.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = Main.decrypt(algorithm, cipherText, key, ivParameterSpec);

        Assert.assertEquals(input, plainText);
    }
}
