package KeyGen;

import java.security.*;
import java.io.*;
import java.util.*;

public class keyGenerator{

    static private Base64.Encoder encoder = Base64.getEncoder();

    static private void writeBase64(Writer out,Key key) throws java.io.IOException {
        byte[] buf = key.getEncoded();
        out.write(encoder.encodeToString(buf));
    }


    static public void generateKeys(String user) throws NoSuchAlgorithmException, IOException {
        int keySize = 1024;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();
        String outFile = user + "Private";
        Writer out = null;
        try {
            out = new FileWriter("KeyGen/" + outFile + ".key");
            writeBase64(out, kp.getPrivate());

            outFile = user + "Public";
            if ( outFile != null ) {
                out.close();
                out = new FileWriter("KeyGen/" + outFile + ".key");
            }
            
            writeBase64(out, kp.getPublic());
        } finally {
            if ( out != null ) out.close();
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        generateKeys("X");
        generateKeys("Y");
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter 16-character string: ");
        String key = sc.next();
        BufferedWriter writer = new BufferedWriter(new FileWriter("KeyGen/symmetric.key"));
        writer.write(key);
        writer.close();
        sc.close();
    }

}