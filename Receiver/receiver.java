// Project 1: Public-key encrypted message and its authentic digital digest
// Completed by Timothy Trusov and Eric Armstrong 
// CS-3750 Dr. Weiying Zhu

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

import java.math.BigInteger;

public class receiver {

    static String ALGORITHM = "AES";
    static String AES_CBC_NoPADDING = "AES/CBC/NoPadding";

    //Getting Private Key and Decoder
    public static PrivateKey getPrivateKey(String filename) throws Exception {
        Scanner sc = new Scanner(new File(filename));
        byte[] decodedBytes = Base64.getDecoder().decode(sc.next());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    //The Conversion method that converts bytes to hex
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

    //Byte Decryptor method
    public static byte[] decrypt(byte[] strToDecrypt, final byte[] key) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException 
    {
        byte[] correctByteNumber4Key = new byte[16];
        for(int i = 0; i < 16; i++){
            correctByteNumber4Key[i] = key[i];
        }
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(AES_CBC_NoPADDING);
        final SecretKeySpec keySpec = new SecretKeySpec(correctByteNumber4Key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivspec);
        return cipher.doFinal(strToDecrypt);
    }

    //RSA Padding and Decrytor
    public static byte[] RSAdecrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    //read key parameters from a file and generate the private key 
    // Got this method from RSAConfidentiality.java
  public static PrivateKey readPrivKeyFromFile(String keyFileName) 
  throws IOException {

    ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)));      

try {
  BigInteger m = (BigInteger) oin.readObject();
  BigInteger e = (BigInteger) oin.readObject();

  System.out.println("Read from " + keyFileName + ": modulus = " + 
      m.toString() + ", exponent = " + e.toString() + "\n");

  RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
  KeyFactory factory = KeyFactory.getInstance("RSA");
  PrivateKey key = factory.generatePrivate(keySpec);

  return key;
} catch (Exception e) {
  throw new RuntimeException("Spurious serialisation error", e);
} finally {
  oin.close();
}
}

    //Main Method 
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String file = sc.next();
        //Method to Recieve Files from Sender 
        try{
            PrivateKey rsaKey = readPrivKeyFromFile("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/YPrivate.key");
            System.out.println("The rsaKey" + rsaKey.toString());
            // PrivateKey rsaKey = getPrivateKey("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/YPrivate.key");
            FileInputStream fin = new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.rsacipher");
            OutputStream as = new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.add-msg"); 
            int i;    
            byte[] data = new byte[128];
            Scanner f = new Scanner(new File("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/symmetric.key"));
            String key = f.next();
            f.close();
            byte[] b = key.getBytes(StandardCharsets.UTF_8);
            while ((i = fin.read(data)) != -1) {
                byte[] rsaDecrypted = RSAdecrypt(data, rsaKey);
                as.write(rsaDecrypted);
            }
            fin.close();
            as.close();
            byte[] array = Files.readAllBytes(Paths.get("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.add-msg"));
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
            OutputStream os = new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/" + file); 
            os.write(message);
            os.close();
            byte[] plainText = decrypt(data, b);
            os = new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.dd"); 
            os.write(plainText);
            os.close();
            System.out.println("Digest: " + bytesToHex(plainText));
            fin = new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/" + file);
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
            System.out.println("Exception: " + e);
        }    
        sc.close();
    }
    
}
