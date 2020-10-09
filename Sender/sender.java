// Project 1: Public-key encrypted message and its authenitic digital digest
// Completed by Timothy Trusov and Eric Armstrong 
// CS-3750 Dr. Weiying Zhu

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
import javax.xml.bind.DatatypeConverter;

import org.graalvm.compiler.nodes.java.InstanceOfDynamicNode;

import java.math.BigInteger;

public class sender {
    
    
public static void main(String[] args) {
    try{
        // TODO: buffer all of my inputs/outputs w/BufferedOutputStream
        
        // Streams and variables
        OutputStream os = new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/message.dd"); 
        OutputStream addmsgOut = new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/message.add-msg"); 
        FileInputStream inputStream2 = new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/message.add-msg");
        BufferedInputStream addmsgIn = new BufferedInputStream(inputStream2); 
        String stringMessage = "";
        String aes = "";
        byte[] data = new byte[1024];
        String algorithm = "AES";
        String padding = "AES/CBC/NoPadding";
        Integer numBytes = 0;
        
        // Get public key 
        PublicKey rsaKey = readPubKeyFromFile("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/YPublic.key");
        System.out.println("Public key: " + rsaKey);

        // Get and generate symmetric key
        Scanner f = new Scanner(new File("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/symmetric.key"));
        String stringKey = f.next();
        System.out.println(stringKey);
        f.close();
        byte[] byteKey = stringKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeyxy = new SecretKeySpec(byteKey,algorithm);
        byte[] primedKeyxy = secretKeyxy.getEncoded();
        
        // Create initilization vector (First two lines only ones used for now)
        SecureRandom secureRandom = new SecureRandom(); 
        byte[] IVBytes = generateKey(algorithm);
        byte[] initializationVector = new byte[16]; 
        secureRandom.nextBytes(initializationVector);

/*             KeyGenerator keygenerator = KeyGenerator.getInstance(algorithm);
        keygenerator.init(256, securerandom);
        Secretkey key = keygenerator.generateKey(); */

        // Get M filename from user
        Scanner sc = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String file = sc.nextLine();
        FileInputStream inputStream = new FileInputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/" + file);
        BufferedInputStream messageBufStream = new BufferedInputStream(inputStream);

        // Read M input and put value into a String variable 
        while(messageBufStream.available() > 0) {
            char c = (char) messageBufStream.read();
            stringMessage += Character.toString(c);
            numBytes++;
        }

        // Create hash of M
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(stringMessage.getBytes(StandardCharsets.UTF_8));
        
        // See if user wants to swap first bit of hash, then save the hash
        System.out.print("Do you want to invert the 1st byte in SHA256(M)? (Y or N)");
        String file2 = sc.nextLine();
        if( file2.equals("yes") || file2.equals("Yes") || file2.equals("Y") || file2.equals("y")) {
            hash = swapFirstByte(hash);
            os.write(hash);
            System.out.println("MODIFIED SHA 256: " + bytesToHex(hash));
        } else {
            os.write(hash);
            System.out.println("SHA 256: " + bytesToHex(hash));
        }
        
        // Encrypt the hash with Kxy key in AES Encryption
        byte[] encryptedHash = encrypt(primedKeyxy, IVBytes, hash, algorithm, padding);
        
        // Write encrypted hash to file and a string variable 
        addmsgOut.write(encryptedHash);
        aes += bytesToHex(encryptedHash);
        System.out.println("AES: " + aes);

        // Append M to message.add-msg
        addmsgOut.write(messageBufStream.readAllBytes()); // Suppose to do this "piece by piece" buttt.....why? 

        data = new byte[117];
        FileOutputStream outputStream = new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/Sender/message.rsacipher"); 
        int i = 0;
        while ((i = addmsgIn.read(data)) != -1) {
            byte[] rsaEncrypted = RSAencrypt(data, rsaKey);
            outputStream.write(rsaEncrypted);
        }

        inputStream.close();
        inputStream2.close();
        addmsgIn.close();
        addmsgOut.close();
        messageBufStream.close();
        outputStream.close();
        os.close();
        sc.close();
    }    
    catch(Exception e){
        System.out.println("Exception thrown: " + e.getLocalizedMessage());
    }    
}

public static PublicKey getPublicKey(String filename) throws Exception {
    Scanner sc = new Scanner(new File(filename));
    byte[] decodedBytes = Base64.getDecoder().decode(sc.next());
    X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
}

//read key parameters from a file and generate the public key 
// (Method taken from RSAConfidentiality.java)
  public static PublicKey readPubKeyFromFile(String keyFileName) 
  throws IOException {

InputStream in = 
    sender.class.getResourceAsStream(keyFileName);
ObjectInputStream oin =
    new ObjectInputStream(new BufferedInputStream(in));

try {
  BigInteger m = (BigInteger) oin.readObject();
  BigInteger e = (BigInteger) oin.readObject();

  System.out.println("Read from " + keyFileName + ": modulus = " + 
      m.toString() + ", exponent = " + e.toString() + "\n");

  RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
  KeyFactory factory = KeyFactory.getInstance("RSA");
  PublicKey key = factory.generatePublic(keySpec);

  return key;
} catch (Exception e) {
  throw new RuntimeException("Spurious serialisation error", e);
} finally {
  oin.close();
}
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

public static byte[] encrypt(final byte[] key, final byte[] IV, final byte[] message, String ALGORITHM, String padding) throws Exception {
    return encryptDecrypt(Cipher.ENCRYPT_MODE, key, IV, message, ALGORITHM, padding);
}

private static byte[] encryptDecrypt(final int mode, final byte[] key, final byte[] IV, 
                                    final byte[] message, String ALGORITHM, String padding) 
                                    throws Exception {
    byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    IvParameterSpec ivspec = new IvParameterSpec(iv);
    final Cipher cipher = Cipher.getInstance(padding);
    final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
    cipher.init(mode, keySpec, ivspec);
    return cipher.doFinal(message);
}

public static byte[] generateKey(String ALGORITHM) throws NoSuchAlgorithmException, InvalidKeySpecException {
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

public static byte[] swapFirstByte(byte[] data) {
    byte[] editedData = data;
    byte newByte;

    newByte = data[0];

/*         System.out.print("OG byte: ");
    System.out.printf("0x%02X",newByte);
    System.out.println(""); */
    
    newByte = (byte) (~newByte);

    editedData[0] = newByte; 

/*         System.out.print("Edited byte: ");
    System.out.printf("0x%02X",editedData[0]);
    System.out.println(""); */

    return editedData;
}
    
}
