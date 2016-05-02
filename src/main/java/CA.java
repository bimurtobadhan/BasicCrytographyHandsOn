import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

import static java.awt.SystemColor.text;


public class CA {

    private String name = "CA";
    private String PRIVATE_KEY_FILE_NAME = "private.key";
    private String PUBLIC_KEY_FILE_NAME  = "public.key";

    private static final String RSA_ALGORITHM = "RSA";

    private File privateKeyFile, publicKeyFile;

    KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public CA() {
        File file = new File(name);
        if(!file.exists() || !file.isDirectory())
            file.mkdirs();

        privateKeyFile = new File(name + "/" +PRIVATE_KEY_FILE_NAME);
        publicKeyFile  = new File(name + "/" + PUBLIC_KEY_FILE_NAME);


        keyPair = generateKeyPair(RSA_ALGORITHM);

        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();


        writeKey(privateKeyFile, privateKey);
        writeKey(publicKeyFile, publicKey);

    }

    public KeyPair generateKeyPair(String algorithm) {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.initialize(2048);
        final KeyPair keypair = keyGen.generateKeyPair();
        return keypair;
    }

    private Key readKey(File file){
        ObjectInputStream inputStream ;
        Key key = null;
        try {
            inputStream = new ObjectInputStream(new FileInputStream(file));
            key = (Key) inputStream.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        return key;
    }

    private void writeKey(File file, Key key){
        ObjectOutputStream privateKeyOS;
        try {
            privateKeyOS = new ObjectOutputStream(
                    new FileOutputStream(file));
            privateKeyOS.writeObject(key);
            privateKeyOS.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] plain, Key secretKey, String algorithm){
        Cipher cipher;
        byte[] byteCipherText = null;
        //System.out.println("Length: "+ plain.length);
        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byteCipherText = cipher.doFinal(plain);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return byteCipherText;
    }

    public byte[] decrypt(byte[] cipherTest, Key secretKey, String algorithm){
        Cipher cipher;
        byte[] byteCipherText = null;
        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byteCipherText = cipher.doFinal(cipherTest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return byteCipherText;
    }

    public void prepareCertificate(String name){
        File file = new File(name + "/" + PUBLIC_KEY_FILE_NAME);
        Key key = readKey(file);
        Certificate certificate = new Certificate(name, key);
        byte[] certifiacteInbytes = objectToBytes(certificate);
        //System.out.println(certifiacteInbytes.length);
        byte[] hash = prepareHash(certifiacteInbytes);
        //System.out.println("Hash:"+convertToHex(hash));
        byte[] encryptedHash = encrypt(hash, privateKey, RSA_ALGORITHM);
        //System.out.println("Encrypted Hash:"+convertToHex(encryptedHash));
        CertificateWrapper wrapper = new CertificateWrapper(certificate, encryptedHash);
        byte[] wrapperInbytes = objectToBytes(wrapper);

        File outputFile = new File(name + "/" + "digital.certificate");
        writeTofile(outputFile, wrapperInbytes);
    }

    private void writeTofile(File file ,byte[] data ){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private byte[] prepareHash(byte[] certifiacteInbytes) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] sha1hash;// = new byte[40];
        md.update(certifiacteInbytes);
        sha1hash = md.digest();
        //System.out.println("Hash:"+convertToHex(sha1hash));
        return sha1hash;
    }

    public byte[] objectToBytes(Object object){
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try{
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(object);
        }catch (IOException e) {
            e.printStackTrace();
        }
        return byteArrayOutputStream.toByteArray();
    }

    public Object bytesToObject(byte[] bytes){
        Object object = null;
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        try{

            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            object = objectInputStream.readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return object;
    }

    public static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9))
                    buf.append((char) ('0' + halfbyte));
                else
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = data[i] & 0x0F;
            } while(two_halfs++ < 1);
        }
        return buf.toString();
    }

}
