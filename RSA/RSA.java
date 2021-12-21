package RSA;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSA {
    private static final String PUBLIC_KEY_FILE = "Public.key";
    private static final String PRIVATE_KEY_FILE = "Private.key";

    public static void main(String[] args) throws IOException {

        try {
            System.out.println("-------GENRATE PUBLIC and PRIVATE KEY-------------");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); 
            // 1024 is concerned in low security.
            
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("Public Key - " + publicKey);
            System.out.println("Private Key - " + privateKey);

            
            System.out.println("\n-------  PARAMETERS WHICH MAKES KEYPAIR----------\n");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            System.out.println("PubKey Modulus : " + rsaPubKeySpec.getModulus());
            System.out.println("PubKey Exponent : " + rsaPubKeySpec.getPublicExponent());
            System.out.println("PrivKey Modulus : " + rsaPrivKeySpec.getModulus());
            System.out.println("PrivKey Exponent : " + rsaPrivKeySpec.getPrivateExponent());

            
            System.out.println("\n--------SAVING PUBLIC  AND PRIVATE  TO FILES-------\n");
            RSA rsaObj = new RSA();
            rsaObj.saveKeys(PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
            rsaObj.saveKeys(PRIVATE_KEY_FILE, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());
            
            byte[] encryptedData = rsaObj.encryptData();

            
            rsaObj.decryptData(encryptedData);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

    }

    
    private void saveKeys(String fileName,BigInteger mod,BigInteger exp) throws IOException{
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;

        try {
            System.out.println("Generating "+fileName + "...");
            fos = new FileOutputStream(fileName);
            oos = new ObjectOutputStream(new BufferedOutputStream(fos));

            oos.writeObject(mod);
            oos.writeObject(exp);

            System.out.println(fileName + " generated successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
        finally{
            if(oos != null){
                oos.close();

                fos.close();
            }
        }
    }

    
    private byte[] encryptData() {
        System.out.println("\n----------------ENCRYPTION STARTED------------");

        System.out.println("Data Before Encryption :" + "aditya  - Classified Information !");
        byte[] dataToEncrypt = "user search - Classified Information !".getBytes();
        byte[] encryptedData = null;
        try {
            PublicKey pubKey = readPublicKeyFromFile(PUBLIC_KEY_FILE);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            for (byte b : encryptedData = cipher.doFinal(dataToEncrypt)) {
                
            }

            System.out.println("Encryted Data: " + encryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("----------------ENCRYPTION COMPLETED------------");
        return encryptedData;
    }


    private void decryptData() throws IOException {
        decryptData();
    }

    private void decryptData(byte[] data) throws IOException {
        System.out.println("\n----------------DECRYPTION STARTED------------");
        byte[] descryptedData;

        try {
            PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            descryptedData = cipher.doFinal(data);
            System.out.println("Decrypted Data: " + new String(descryptedData));

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("----------------DECRYPTION COMPLETED------------");
    }

    
    public PublicKey readPublicKeyFromFile(String fileName) throws IOException {
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            fis = new FileInputStream(new File(fileName));
            ois = new ObjectInputStream(fis);

            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger exponent = (BigInteger) ois.readObject();

            
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);

            return publicKey;

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (ois != null) {
                ois.close();
                if (fis != null) {
                    fis.close();
                }
            }
        }
        return null;
    }
    public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try {
            fis = new FileInputStream(new File(fileName));
            ois = new ObjectInputStream(fis);

            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger exponent = (BigInteger) ois.readObject();

            //Get Private Key
            RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);

            return privateKey;

        } catch (Exception e) {
            e.printStackTrace();
        }
        finally{
            if(ois != null){
                ois.close();
                fis.close();
            }
        }
        return null;
    }
}

