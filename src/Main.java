import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        int number  = 128;
        String password = "Bluecoder01";
        String salt = "isfjnvervejv";
        String algorithm = "AES/CBC/PKCS5Padding";
        String input = "Seun1";
        SecretKey secretKey = generateKey(number);
        IvParameterSpec iv = generateIv();

        System.out.println("Secret key from number: "+generateKey(number).getEncoded());
        System.out.println("Secret key from password: "+generateKeyFromPassword(password, salt).getEncoded());
        System.out.println("Initialization Vector(Iv): "+generateIv().getIV());

        System.out.println("Encrypting a string: "+ encrypt(algorithm, input, secretKey, iv));
        String cipher = encrypt(algorithm, input, secretKey, iv);
        System.out.println("Decypting a string: "+ decrypt(algorithm, cipher, secretKey, iv));

    }
    //generating secret key from a number
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    //generating secret key from a password
    public static SecretKey generateKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secretKey = new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
        return secretKey;
    }
    //generating an initialization vector
    public static IvParameterSpec generateIv(){
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
//encrypting a string
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
}
