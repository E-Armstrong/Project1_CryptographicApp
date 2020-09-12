import java.util.ArrayList;
import java.Security;

public class KeyGen {

    public static void main (String [ ] args) { 
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        // Key size is set to 2048 but don't know what it's suppose to be set at
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Generate key pair for X
        Key Xpub = kp.getPublic();
        Key Xpvt = kp.getPrivate();

        // I don't know if it's neccessary to regenerate the key pair
        // group (kpg) but I did it anyways
        KeyPair kp2 = kpg.generateKeyPair();

        // Generate key pair for Y
        Key Ypub = kp.getPublic();
        Key Ypvt = kp.getPrivate();

        // This is just code pasted from https://www.novixys.com/blog/how-to-generate-rsa-keys-java/
        // Don't know if we need it yet. 
        String outFile = ...;
        out = new FileOutputStream(outFile + ".key");
        out.write(pvt.getEncoded());
        out.close();

        out = new FileOutputStream(outFile + ".pub");
        out.write(pvt.getEncoded());
        out.close();

    } // End main

 } // End class