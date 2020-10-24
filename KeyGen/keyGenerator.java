// Project 1: Public-key encrypted message and its authenitic digital digest
// Completed by Timothy Trusov and Eric Armstrong 
// CS-3750 Dr. Weiying Zhu

import java.io.*;
import java.util.*;

import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;

import javax.crypto.Cipher; 

public class keyGenerator {    
    public static void main(String[] args) throws Exception {
    
        //Generate a pair of keys
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        /* next, store the keys to files, read them back from files, 
           and then, encrypt & decrypt using the keys from files. */
    
        //get the parameters of the keys: modulus and exponet
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, 
            RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, 
            RSAPrivateKeySpec.class);
    
        //save the parameters of the keys to the files
        saveToFile("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/KeyGen/YPublic.key", pubKSpec.getModulus(), 
            pubKSpec.getPublicExponent());
        saveToFile("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/KeyGen/YPrivate.key", privKSpec.getModulus(), 
            privKSpec.getPrivateExponent());
      
        // Create symmertric key
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter 16-character string: ");
        String key = sc.next();
        ObjectOutputStream writer = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("/Users/eggsaladsandwich/Box Sync/School/CS-3750/Project1/KeyGen/symmetric.key")));
        writer.writeObject(key);
        writer.close();
        sc.close();
      
        }
    
    
      //save the prameters of the public and private keys to file
      public static void saveToFile(String fileName,
            BigInteger mod, BigInteger exp) throws IOException {
    
        System.out.println("Write to " + fileName + ": modulus = " + 
            mod.toString() + ", exponent = " + exp.toString() + "\n");
    
        ObjectOutputStream oout = new ObjectOutputStream(
          new BufferedOutputStream(new FileOutputStream(fileName)));
    
        try {
          oout.writeObject(mod);
          oout.writeObject(exp);
        } catch (Exception e) {
          throw new IOException("Unexpected error", e);
        } finally {
          oout.close();
        }
      }
    
    
      //read key parameters from a file and generate the public key 
      public static PublicKey readPubKeyFromFile(String keyFileName) 
          throws IOException {
    
        InputStream in = 
            RSAConfidentiality.class.getResourceAsStream(keyFileName);
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
    
    
      //read key parameters from a file and generate the private key 
      public static PrivateKey readPrivKeyFromFile(String keyFileName) 
          throws IOException {
    
        InputStream in = 
            RSAConfidentiality.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
            new ObjectInputStream(new BufferedInputStream(in));
    
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
    
    