package Sender;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class sender {

    static String ALGORITHM = "AES";
    static String AES_CBC_NoPADDING = "AES/CBC/NoPadding";


    public static PublicKey getPublicKey(String filename) throws Exception {
        Scanner sc = new Scanner(new File(filename));
        byte[] decodedBytes = Base64.getDecoder().decode(sc.next());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] encrypt(final byte[] key, final byte[] IV, final byte[] message) throws Exception {
        return encryptDecrypt(Cipher.ENCRYPT_MODE, key, IV, message);
    }

    private static byte[] encryptDecrypt(final int mode, final byte[] key, final byte[] IV, final byte[] message) throws Exception {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        final Cipher cipher = Cipher.getInstance(AES_CBC_NoPADDING);
        final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(mode, keySpec, ivspec);
        return cipher.doFinal(message);
    }

    public static byte[] generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }

    public static byte[] RSAencrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String file = sc.next();
        try{
            FileInputStream fin = new FileInputStream("Sender/" + file);
            OutputStream os = new FileOutputStream("Sender/message.dd"); 
            OutputStream as = new FileOutputStream("Sender/message.add-msg"); 
            int i;    
            String sha = "";
            String aes = "";
            byte[] data = new byte[1024];
            Scanner f = new Scanner(new File("Sender/symmetric.key"));
            String key = f.next();
            f.close();
            byte[] b = key.getBytes(StandardCharsets.UTF_8);
            byte IVBytes[] = generateKey();
            while ((i = fin.read(data)) != -1) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedhash = digest.digest(data);
                sha += bytesToHex(encodedhash);
                os.write(encodedhash); 
                byte[] cipherText = encrypt(b, IVBytes, encodedhash);
                aes += bytesToHex(cipherText);
                as.write(cipherText);
                as.write(data);
            }
            System.out.println("SHA 256: " + sha);
            System.out.println("AES: " + aes);
            fin.close();
            as.close();
            os.close();
            PublicKey rsaKey = getPublicKey("Sender/YPublic.key");
            data = new byte[117];
            fin = new FileInputStream("Sender/message.add-msg");
            os = new FileOutputStream("Sender/message.rsacipher"); 
            while ((i = fin.read(data)) != -1) {
                byte[] rsaEncrypted = RSAencrypt(data, rsaKey);
                os.write(rsaEncrypted);
            }
            fin.close();
            os.close();
        }    
        catch(Exception e){
            System.out.println(e);
        }    
        sc.close();
    }
    
}
