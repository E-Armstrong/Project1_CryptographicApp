import java.util.ArrayList;
import java.Security;

public class KeyGen {

    public static void main (String [ ] args) { 
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Generate key pair for X
        Key Xpub = kp.getPublic();
        Key Xpvt = kp.getPrivate();

        KeyPair kp2 = kpg.generateKeyPair();

        // Generate key pair for Y
        Key Ypub = kp.getPublic();
        Key Ypvt = kp.getPrivate();

        String outFile = ...;
        out = new FileOutputStream(outFile + ".key");
        out.write(pvt.getEncoded());
        out.close();

        out = new FileOutputStream(outFile + ".pub");
        out.write(pvt.getEncoded());
        out.close();

    } // End main

 } // End class