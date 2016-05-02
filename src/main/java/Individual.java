import javax.crypto.*;
import java.io.*;
import java.security.*;

/**
 * Created by Shawrup on 4/22/2016.
 */
public class Individual {

    private String name;

    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey secretKey,macKey;

    private String PRIVATE_KEY_FILE_NAME = "private.key";
    private String PUBLIC_KEY_FILE_NAME  = "public.key";
    private String SECRET_KEY_FILE_NAME = "secret.key";
    private String MAC_KEY_FILE_NAME = "mac.key";
    private String MESSAGE_FILE_NAME = "message.txt";
    private String MAC_CODE_FILE_NAME = "mac_code.txt";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "HmacSHA1";

    private File privateKeyFile, publicKeyFile, secretKeyFile, macKeyFile, mac_CodeFile;

    String message = null;

    public Individual(String name) {
        File file = new File(name);
        if(!file.exists() || !file.isDirectory())
            file.mkdirs();

        this.name = name;

        privateKeyFile = new File(name + "/" +PRIVATE_KEY_FILE_NAME);
        publicKeyFile  = new File(name + "/" + PUBLIC_KEY_FILE_NAME);
        secretKeyFile = new File(name + "/" + SECRET_KEY_FILE_NAME);
        macKeyFile = new File(name + "/" + MAC_KEY_FILE_NAME);
        mac_CodeFile = new File(name +"/" + MAC_CODE_FILE_NAME);
        File outputFile = new File(name + "/" + "digital.certificate");

        keyPair = generateKeyPair(RSA_ALGORITHM);

        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        secretKey = geneRateSecretKey();
        macKey = generatemacKey();

        writeKey(privateKeyFile, privateKey);
        writeKey(publicKeyFile, publicKey);
        writeKey(secretKeyFile, secretKey);
        writeKey(macKeyFile, macKey);
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

    public SecretKey geneRateSecretKey(){
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.init(128);

        SecretKey secretKey = keyGen.generateKey();
        return  secretKey;
    }

    public SecretKey generatemacKey(){
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKey secretKey = keyGen.generateKey();
        return  secretKey;
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

    public void secretKeyTest(){
        System.out.println("TEst:");
        String test = "hello world";
        byte [] plain = test.getBytes();
        //SecretKey key = geneRateSecretKey();
        byte[] chiphertext = encrypt(plain,secretKey,AES_ALGORITHM);
        plain = decrypt(chiphertext,secretKey,AES_ALGORITHM);
        String res = new String(plain);
        System.out.println(res);
    }

    public void sendKey(String name, Object object, Key key){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        byte[] plaindata = objectToBytes(object);
        byte[] encrypteddata = encrypt(plaindata, key, RSA_ALGORITHM);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(encrypteddata);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void readSecretKey(){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        byte[] encrypteddata = fileTobytes(file);
        byte[] plaindata = decrypt(encrypteddata, privateKey, RSA_ALGORITHM);
        secretKey = (SecretKey) bytesToObject(plaindata);
    }

    public void sendMessage(String name, Object message){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        byte[] plaindata = objectToBytes(message);
        byte[] encrypteddata = encrypt(plaindata, secretKey, AES_ALGORITHM);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(encrypteddata);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    public void readMessage(){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        byte[] encrypteddata = fileTobytes(file);
        byte[] plaindata = decrypt(encrypteddata, secretKey, AES_ALGORITHM);
        message = (String) bytesToObject(plaindata);
        System.out.println(message);
    }


    public void sendPlainMessage(String name,  byte[] message){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(message);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void readPlainMessage(){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        byte[] plaindata = fileTobytes(file);
        message = new String(plaindata);
        System.out.println("Plain Message: " + message);
    }

    public void sendMac(String name,  byte[] message){
        File file = new File(name + "/" + MAC_CODE_FILE_NAME);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(message);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void verifyMac(){
        File file = new File(name + "/" + MAC_CODE_FILE_NAME);
        byte[] mac = fileTobytes(file);
        System.out.println(message);
        byte[] macFormMsg = prepareMacDigest(macKey, message);
        for(int i=0;i<mac.length;i++){
            if(mac[i] != macFormMsg[i]) {
                System.out.println("Message Altered");
                return;
            }
        }
        System.out.println("Message is authenticated");
    }


    public byte[] fileTobytes(File file){
        FileInputStream fin = null;
        byte fileContent[] = null;
        try {
            fin = new FileInputStream(file);
            fileContent = new byte[(int)file.length()];
            fin.read(fileContent);
        }
        catch (FileNotFoundException e) {
            System.out.println("File not found" + e);
        }
        catch (IOException ioe) {
            System.out.println("Exception while reading file " + ioe);
        }
        finally {
            try {
                if (fin != null) {
                    fin.close();
                }
            }
            catch (IOException ioe) {
                System.out.println("Error while closing stream: " + ioe);
            }
        }
        return fileContent;
    }

    public void RSAtest(){
        String test = "hello world";
        byte [] plain = test.getBytes();

        String res = new String(plain);
        System.out.println(res);
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

    public void readMacKey(){
        File file = new File(name + "/" + MESSAGE_FILE_NAME);
        byte[] encrypteddata = fileTobytes(file);
        byte[] plaindata = decrypt(encrypteddata, privateKey, RSA_ALGORITHM);
        macKey = (SecretKey) bytesToObject(plaindata);
    }


    public Key readCertificate(String name){
        File file = new File(name +"/" + "digital.certificate");
        byte[] certificateWrapperInbytes = fileTobytes(file);
        CertificateWrapper wrapper = (CertificateWrapper) bytesToObject(certificateWrapperInbytes);
        Certificate certificate = wrapper.certificate;
        byte[] certificateHash = prepareHash(certificate);
        //System.out.println("Hash:"+CA.convertToHex(certificateHash));
        //System.out.println(certificateHash.length);
        byte[] encryptedHash = wrapper.encryptedhash;
        //System.out.println("Encrypted Hash:"+CA.convertToHex(encryptedHash));
        Key key = readKey(new File("CA/"+PUBLIC_KEY_FILE_NAME));
        byte[] decryptedHash = decrypt(encryptedHash, key, RSA_ALGORITHM);
        //System.out.println(decryptedHash.length);
        for(int i=0;i<certificateHash.length;i++){
            if(certificateHash[i] != decryptedHash[i]){
                System.out.println("Not match");
                return null;
            }
        }
        if(!name.equals(certificate.owner)) {
            System.out.println("not match");
        }
        System.out.println("Certificate Verified");

        return certificate.key;
    }

    private byte[] prepareHash(Object object){
        byte[] bytes = objectToBytes(object);
        return prepareHash(bytes);
    }

    private byte[] prepareHash(byte[] certifiacteInbytes) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] sha1hash = new byte[40];
        md.update(certifiacteInbytes);
        sha1hash = md.digest();
        return sha1hash;
    }


    public byte[] prepareMacDigest(SecretKey macKey, String message){
        // create a MAC and initialize with the above key
        Mac mac = null;
        try {
            mac = Mac.getInstance(macKey.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            mac.init(macKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte[] b = new byte[0];
        try {
            b = message.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        // create a digest from the byte array
        byte[] digest = mac.doFinal(b);
        return digest;
    }




    public static void main(String[] args) {
        Individual alice = new Individual("Alice");
        Individual bob = new Individual("Bob");

        //------------------------------------------
        System.out.println("First Test: ");
        alice.sendKey("Bob", alice.getSecretKey(), bob.getPublicKey());
        bob.readSecretKey();
        //alice.secretKeyTest();
        String msg = "Hello";
        System.out.println("Sent Message: " + msg);
        alice.sendMessage("Bob", msg);
        bob.readMessage();

        //------------------------------------------
        System.out.println("Second Test: ");
        alice.sendKey("Bob", alice.getMacKey(), bob.getPublicKey());
        bob.readMacKey();
        msg = "Hello World";
        alice.sendPlainMessage("Bob", msg.getBytes());
        System.out.println("Sent Plain Message: " + msg);
        System.out.print("Received ");
        bob.readPlainMessage();
        byte[] macdata = alice.prepareMacDigest(alice.getMacKey(), msg);
        alice.sendMac("Bob", macdata);
        System.out.println("Mac Verification: ");
        bob.verifyMac();

        //------------------------------------------

        System.out.println("Third Test: ");
        CA ca = new CA();

        ca.prepareCertificate("Bob");

        PublicKey key = (PublicKey) alice.readCertificate("Bob");
        if(key == null)
            return;

        //alice.setSecretKey(key);
        alice.sendKey("Bob", alice.getSecretKey(), key);
        bob.readSecretKey();
        //alice.secretKeyTest();

        msg = "hello";
        System.out.println("Sent Message: " + msg);
        alice.sendMessage("Bob", msg);
        System.out.println("Received message: ");
        bob.readMessage();
    }


    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public SecretKey getMacKey() {
        return macKey;
    }
}
