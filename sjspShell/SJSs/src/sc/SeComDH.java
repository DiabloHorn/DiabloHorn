package sc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import sun.security.provider.DSAPrivateKey;

/**
 *
 * @author http://diablohorn.wordpress.com
 * Borrowed, reused, modified and changed code from the following resources:
 * http://stackoverflow.com/questions/992019/java-256bit-aes-encryption
 * http://www.javaworld.com/javaworld/jw-12-2000/jw-1229-traps.html?page=4
 * http://java.sun.com/developer/technicalArticles/Security/AES/AES_v1.html
 * http://www.devdaily.com/java/edu/pj/pj010011
 * http://www.jsptut.com/Sessions.jsp
 *
 * This class is a modified version of the code on the following URL
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
 *
 * With some addition of code on the following URL
 * http://stackoverflow.com/questions/992019/java-256bit-aes-encryption
 *
 * More addition from code on the following URL
 * http://docs.oracle.com/javase/tutorial/security/apisign/index.html
 * http://www.java2s.com/Tutorial/Java/0490__Security/RSASignatureGeneration.htm
 *
 */
public class SeComDH {
/*
 * Class variables start here
 */
    //alice
    private DHParameterSpec dhSkipParamSpec = null;
    private KeyPair aliceKpair = null;
    private KeyAgreement aliceKeyAgree = null;
    private byte[] aliceSharedSecret = null;
    //bob
    private KeyPair bobKpair = null;
    private KeyAgreement bobKeyAgree = null;
    private byte[] bobSharedSecret = null;
    //other
    private PublicKey publicKeyFromAlice = null;
/*
 * Class variables end here
 */

/*
 * helper methods start here
 */
    public static String asHex(byte buf[]) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }

        return strbuf.toString();
    }

    public static byte[] asByte(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    //create dh parameters
    private void createDHParameterSpec(int keysize) throws NoSuchAlgorithmException, InvalidParameterSpecException{
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(keysize,new SecureRandom());
        AlgorithmParameters params = paramGen.generateParameters();
        this.dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
    }

    private void createDHParameterSpec() throws NoSuchAlgorithmException, InvalidParameterSpecException{
        createDHParameterSpec(1024);
    }
    
    /*
     * Alice creates her own DH key pair, using the DH parameters from
     * above
     */
    private void AliceCreateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException{
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(this.dhSkipParamSpec);
        this.aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        this.aliceKeyAgree = KeyAgreement.getInstance("DH");
        this.aliceKeyAgree.init(this.aliceKpair.getPrivate());
    }

    public String getAlicePublicKey(){
        return SeComDH.asHex(this.aliceKpair.getPublic().getEncoded());
    }

    private void BobCreateKeyPair(byte[] PublicKeyFromAlice) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException{
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(PublicKeyFromAlice);
        this.publicKeyFromAlice = bobKeyFac.generatePublic(x509KeySpec);

        DHParameterSpec dhParamSpec = ((DHPublicKey) this.publicKeyFromAlice).getParams();

        // Bob creates his own DH key pair
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamSpec);
        this.bobKpair = bobKpairGen.generateKeyPair();

        // Bob creates and initializes his DH KeyAgreement object
        this.bobKeyAgree = KeyAgreement.getInstance("DH");
        this.bobKeyAgree.init(this.bobKpair.getPrivate());
    }

    public String getBobPublicKey(){
        return SeComDH.asHex(this.bobKpair.getPublic().getEncoded());
    }

    public void aliceGenerateSecret(byte[] PublicKeyFromBob) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException{
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(PublicKeyFromBob);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        this.aliceKeyAgree.doPhase(bobPubKey, true);
        this.aliceSharedSecret = this.aliceKeyAgree.generateSecret();
    }

    public void bobGenerateSecret() throws InvalidKeyException{
        this.bobKeyAgree.doPhase(this.publicKeyFromAlice, true);
        this.bobSharedSecret = this.bobKeyAgree.generateSecret();
    }

    public String getAliceSharedSecret(){
        return SeComDH.asHex(this.aliceSharedSecret);
    }

    public String getBobSharedSecret(){
        return SeComDH.asHex(this.bobSharedSecret);
    }
    
    //init as Alice
    public SeComDH() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidParameterSpecException{
        createDHParameterSpec();
        AliceCreateKeyPair();
    }

    //init as Alice
    public SeComDH(int keysize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidParameterSpecException{
        createDHParameterSpec(keysize);
        AliceCreateKeyPair();
    }
    
    //init as Bob
    public SeComDH(byte[] AlicePublicKey) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException{
        BobCreateKeyPair(AlicePublicKey);
    }

    public static String md5(String data) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("MD5");
        return SeComDH.asHex(md.digest(SeComDH.asByte(data)));
    }
    public static String[] encryptBlowfish(String plain,String encKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidParameterSpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        SecretKeySpec key = new SecretKeySpec(SeComDH.asByte(encKey), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plain.getBytes("ASCII"));
        return new String[]{SeComDH.asHex(ciphertext),SeComDH.asHex(iv)};
    }

    public static String decryptBlowfish(String crypt,String decKey,String iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        SecretKeySpec key = new SecretKeySpec(SeComDH.asByte(decKey), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(SeComDH.asByte(iv)));
        return new String(cipher.doFinal(SeComDH.asByte(crypt)),"ASCII");
    }

    private static void writeFile(String path,byte[] data) throws FileNotFoundException, IOException{
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(data);
        fos.close();
    }

    private static byte[] readFile(String path) throws FileNotFoundException, IOException{
        FileInputStream keyfis = new FileInputStream(path);
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read(encKey);
        keyfis.close();
        return encKey;
    }

    private static byte[] readFileFromStream(InputStream in) throws IOException{
        byte[] encKey = new byte[in.available()];
        in.read(encKey);
        in.close();
        return encKey;
    }
    public static void generateDSAKeyPair(String storePublicKeyPath,String storePrivateKeyPath) throws NoSuchAlgorithmException, FileNotFoundException, IOException, NoSuchProviderException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024,new SecureRandom());
        KeyPair keypair = keyGen.genKeyPair();
        SeComDH.writeFile(storePublicKeyPath, keypair.getPublic().getEncoded());
        SeComDH.writeFile(storePrivateKeyPath,keypair.getPrivate().getEncoded());
    }

    public static byte[] signWithDSA(byte[] data,String privateKeyPath) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, FileNotFoundException, IOException, NoSuchProviderException{
        byte[] privateKey = SeComDH.readFile(privateKeyPath);
        //X509EncodedKeySpec prvKeySpec = new X509EncodedKeySpec(privateKey);
        //KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        //PrivateKey pk = keyFactory.generatePrivate(prvKeySpec);
        DSAPrivateKey pk = new DSAPrivateKey(privateKey);
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(pk, new SecureRandom());
        signature.update(data);
        return signature.sign();
    }

    public static byte[] signWithDSA(byte[] data, InputStream privateKeyPath) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, FileNotFoundException, IOException, NoSuchProviderException {
        byte[] privateKey = SeComDH.readFileFromStream(privateKeyPath);
        //X509EncodedKeySpec prvKeySpec = new X509EncodedKeySpec(privateKey);
        //KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        //PrivateKey pk = keyFactory.generatePrivate(prvKeySpec);
        DSAPrivateKey pk = new DSAPrivateKey(privateKey);
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(pk, new SecureRandom());
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifyWithDSA(byte[] data,byte[] sig,String publicKeyPath) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, FileNotFoundException, IOException, NoSuchProviderException{
        byte[] publicKey = SeComDH.readFile(publicKeyPath);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey pk = keyFactory.generatePublic(pubKeySpec);
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initVerify(pk);
        signature.update(data);
        return signature.verify(sig);
    }

    public static boolean verifyWithDSA(byte[] data, byte[] sig, InputStream is) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, FileNotFoundException, IOException, NoSuchProviderException {
        byte[] publicKey = SeComDH.readFileFromStream(is);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey pk = keyFactory.generatePublic(pubKeySpec);
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initVerify(pk);
        signature.update(data);
        return signature.verify(sig);
    }
}
