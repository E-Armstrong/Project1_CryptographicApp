// Project 1: Public-key encrypted message and its authentic digital digest
// Eric Armstrong 
// CS-3750 Dr. Weiying Zhu

//package Receiver;

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
    
    //Main Method 
    public static void main(String[] args) {
        
        try{
                        
            // Step 2
            // Get and generate private key
            PrivateKey privateKey = readPrivKeyFromFile("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/YPrivate.key");
            System.out.println("The rsaKey" + privateKey.toString());
    
            // Get and generate symmetric key
            ObjectInputStream symmetricKeyIn = new ObjectInputStream(
                new BufferedInputStream(new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/symmetric.key")));
            String symmetricString = (String) symmetricKeyIn.readObject();
            SecretKeySpec secretKeyxy = new SecretKeySpec(symmetricString.getBytes("UTF-8"), "AES"); 
            // byte[] primedKeyxy = secretKeyxy.getEncoded();
            
            // Step 3
            // Get message file name from user
            Scanner sc = new Scanner(System.in);
            System.out.print("Input the name of the message file: "); 
            String messageFileName = sc.next();
            sc.close();
            
            // Step 4
            // Get cypher file            
            FileInputStream inputStream = new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.rsacipher");
            BufferedInputStream cypherBufStream = new BufferedInputStream(inputStream);
            
            // Decrypt M and H using RSA encyption
            BufferedOutputStream addmsgOut = new BufferedOutputStream(new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.add-msg")); 
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] piece3 = new byte[128];
            int e;
            ByteArrayOutputStream out4 = new ByteArrayOutputStream();
            while ((e = cypherBufStream.read(piece3)) != -1) {
                out4.write(piece3, 0, e);
                out4.flush();
                addmsgOut.write(cipher.doFinal(out4.toByteArray()));
                out4.reset();
            }
            addmsgOut.flush();
    
            // Step 5
            // Read encrypted hash (or authentic digital digest) from add-msg
            BufferedInputStream addmsgIn = new BufferedInputStream(new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.add-msg"));
            ByteArrayOutputStream out2 = new ByteArrayOutputStream();
            byte[] buffer2 = new byte[32];
            int k = 0;
            while ((k = addmsgIn.read(buffer2)) != -1) {
                out2.write(buffer2, 0, k);
                break;
            }
            byte[] encryptedHash = out2.toByteArray();
            
            // Copy rest of message from message.add-msg to user named message
            BufferedOutputStream messageOut = new BufferedOutputStream(new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/" + messageFileName));
            byte[] piece2 = new byte[1024 * 20];
            int n;
            while ((n = addmsgIn.read(piece2)) != -1) {
                messageOut.write(Arrays.copyOfRange(piece2, 0, n));
            }
    
            // Decrypt encrypted hash (authentic digital digest) and display it
            Cipher cipher2 = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
            cipher2.init(Cipher.DECRYPT_MODE, secretKeyxy, new IvParameterSpec("0000000000000000".getBytes("UTF-8")));
            byte[] digitalDigest = cipher2.doFinal(encryptedHash);
            System.out.println("Decrypted Hash:  " + bytesToHex(digitalDigest));
    
    
            // Write decrypted authentic digital digest to file 
            BufferedOutputStream ddOut = new BufferedOutputStream(new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/message.dd"));
            ddOut.write(digitalDigest);
            ddOut.close();
            
            // Step 6
            // Read and save M input
            BufferedInputStream messageBufStream = new BufferedInputStream(new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Receiver/" + messageFileName));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024 * 10];
            int m = 0;
            while ((m = messageBufStream.read(buffer)) != -1) {
                out.write(buffer, 0, m);
            }
            byte[] byteMessage = out.toByteArray();
    
            // Create hash of M and display it 
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] calculatedHash = digest.digest(byteMessage);
            System.out.println("Calculated Hash: " + bytesToHex(calculatedHash));
    
            // Compare dyrcypted hash (authentic digital digest) with calculated hash and display results
            if(bytesToHex(calculatedHash).equals(bytesToHex(digitalDigest))){
                System.out.println("Accepted! Digital digest passes the authentication check.");
            }
            else{
                System.out.println("Rejected. Digital digest does NOT pass the authentication check.");
            }
            out.close();
            out2.close();
            symmetricKeyIn.close();
            messageOut.close();
            addmsgOut.close();
            messageBufStream.close();
            inputStream.close();
            cypherBufStream.close();
            addmsgIn.close();
        }    
        catch(Exception e){
            System.out.println("Exception: " + e);
        }    
    }
    
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
            hexString.append(" ");
            hexString.append(hex);
        }
        return hexString.toString();
    }

    //Byte Decryptor method
    public static byte[] decrypt(byte[] strToDecrypt, final byte[] key) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
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
    // Method from RSAConfidentiality.java
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

    
}
