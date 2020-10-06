package Receiver;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.NoSuchPaddingException;

public class receiver {

    static String ALGORITHM = "AES";
    static String AES_CBC_NoPADDING = "AES/CBC/NoPadding";

    public static PrivateKey getPrivateKey(String filename) throws Exception {
        Scanner sc = new Scanner(new File(filename));
        byte[] decodedBytes = Base64.getDecoder().decode(sc.next());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
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

    public static byte[] decrypt(byte[] strToDecrypt, final byte[] key) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException 
    {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_CBC_NoPADDING);
        final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivspec);
        return cipher.doFinal(strToDecrypt);
    }

    public static byte[] RSAdecrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String file = sc.next();
        try{
            PrivateKey rsaKey = getPrivateKey("Receiver/YPrivate.key");
            FileInputStream fin = new FileInputStream("Receiver/message.rsacipher");
            OutputStream as = new FileOutputStream("Receiver/message.add-msg"); 
            int i;    
            byte[] data = new byte[128];
            Scanner f = new Scanner(new File("Receiver/symmetric.key"));
            String key = f.next();
            f.close();
            byte[] b = key.getBytes(StandardCharsets.UTF_8);
            while ((i = fin.read(data)) != -1) {
                byte[] rsaDecrypted = RSAdecrypt(data, rsaKey);
                as.write(rsaDecrypted);
            }
            fin.close();
            as.close();
            byte[] array = Files.readAllBytes(Paths.get("Receiver/message.add-msg"));
            data = new byte[32];
            byte[] message = new byte[array.length - 32];
            for(i = 0; i < array.length; i++){
                if(i < 32){
                    data[i] = array[i];
                }
                else{
                    message[i-32] = array[i];
                }
            }
            OutputStream os = new FileOutputStream("Receiver/" + file); 
            os.write(message);
            os.close();
            byte[] plainText = decrypt(data, b);
            os = new FileOutputStream("Receiver/message.dd"); 
            os.write(plainText);
            os.close();
            System.out.println("Digest: " + bytesToHex(plainText));
            fin = new FileInputStream("Receiver/" + file);
            data = new byte[1024];
            String sha = "";
            while ((i = fin.read(data)) != -1) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedhash = digest.digest(data);
                sha += bytesToHex(encodedhash);
                break;
            }
            System.out.println("Calculated Hash: " + sha);
            if(sha.equals(bytesToHex(plainText))){
                System.out.println("Authentic");
            }
            else{
                System.out.println("Corrupt");
            }
            fin.close();
        }    
        catch(Exception e){
            System.out.println(e);
        }    
        sc.close();
    }
    
}
