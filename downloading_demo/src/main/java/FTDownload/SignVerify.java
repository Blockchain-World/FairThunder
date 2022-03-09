package FTDownload;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SignVerify {
    private static String privKeyPath;
    private static String pubKeyPath;

    public static KeyPair generateSignKeyPair(String role) throws Exception {
        if (role.equals("PROVIDER")) {
            privKeyPath = "src/main/resources/Provider/private_key_p.der";
            pubKeyPath = "src/main/resources/Provider/public_key_p.der";
        } else if (role.equals("DELIVERER")) {
            privKeyPath = "src/main/resources/Deliverer/private_key_d.der";
            pubKeyPath = "src/main/resources/Deliverer/public_key_d.der";
        } else if (role.equals("CONSUMER")) {
            privKeyPath = "src/main/resources/Consumer/private_key_c.der";
            pubKeyPath = "src/main/resources/Consumer/public_key_c.der";
        } else {
            System.out.println("Not available");
        }

        // System.out.println("privKeyPath: " + privKeyPath);
        // System.out.println("pubKeyPath: " + pubKeyPath);
        byte[] privBytes = Files.readAllBytes(Paths.get(privKeyPath));
        byte[] pubBytes = Files.readAllBytes(Paths.get(pubKeyPath));

        // private key
        KeySpec keySpec = new PKCS8EncodedKeySpec(privBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        //public key
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(pubBytes);
        PublicKey publicKey = keyFactory.generatePublic(X509publicKey);
        return new KeyPair(publicKey, privateKey);
    }

    public static byte[] generateSignature(PrivateKey signPrivateKey, byte[] data) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initSign(signPrivateKey);
        dsa.update(data);
        return dsa.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] data, byte[] sig) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withRSA");
        dsa.initVerify(publicKey);
        dsa.update(data);
        return dsa.verify(sig);
    }

    // Generate SK
    private static String getPEMPrivateKeyFromDER(PrivateKey privateKey) {
        Base64 base64 = new Base64();
        String begin = "-----BEGIN PRIVATE KEY-----";
        String end = "-----END PRIVATE KEY-----";
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        String key = new String(base64.encode(pkcs8EncodedKeySpec.getEncoded()));
        return begin + "\n" + key + "\n" + end;
    }

    // Generate PK
    private static String getPEMPublicKeyFromDER(PublicKey publicKey) {
        Base64 base64 = new Base64();
        String begin = "-----BEGIN PUBLIC KEY-----";
        String end = "-----END PUBLIC KEY-----";
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(publicKey.getEncoded());
        String key = new String(base64.encode(pkcs8EncodedKeySpec.getEncoded()));
        return begin + "\n" + key + "\n" + end;
    }
    // Driver program
    //    public static void main(String[] args) {
    //        String message = "12345";
    //
    //        // SignVerify.generateSignature()
    //        try {
    //           byte[] signature = SignVerify.generateSignature(SignVerify.generateSignKeyPair("DELIVERER").getPrivate(), message.getBytes());
    //            // System.out.println("Provider signature: " + new String(Base64.encodeBase64(signature)));
    //            System.out.println("Verify: " + SignVerify.verifySignature(SignVerify.generateSignKeyPair("DELIVERER").getPublic(), message.getBytes(), signature));
    //        } catch (Exception e) {
    //            e.printStackTrace();
    //        }
    //
    //    }

}