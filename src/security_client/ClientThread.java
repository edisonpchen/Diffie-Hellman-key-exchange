package security_client;

import java.net.Socket;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientThread extends Thread {
  private Socket socket = null;
  private PrintWriter out = null;
  private BufferedReader in = null;
  private PublicKey serverPubKey = null;
  private SecretKey encKey = null;
  private SecretKey authKey = null;
  private int id = 0;

  public void serverConnect(String hostname, int port) throws Exception {
    socket = new Socket(hostname,port);
    out = new PrintWriter(socket.getOutputStream(),true);
    in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
  }
  public void sendStr(String label, String s) throws Exception{
    out.println(s);
    //System.out.println(getId()+" --> "+label+": "+s);
  }
  public String rcvStr(String label) throws Exception{
    String s = in.readLine();
    //System.out.println("<-- "+label+": "+s);
    return s;
  }
  public void authenticate(boolean verified) throws Exception{
    if(verified) {
      sendStr("verified","OK");
    } else {
      sendStr("verified","ERROR");
      socket.close();
    }
  }
  public BigInteger getG2Y(BigInteger g, BigInteger y, BigInteger p) {
    long time_start = System.nanoTime();
    BigInteger g2y = g.modPow(y,p);
    long time_elapsed = System.nanoTime() - time_start;
    System.out.println(getId()+" (time) 1 generated G^y in       : "+time_elapsed);
    return g2y;
  }

  //helpers from SrvThread
  public byte[] str2byte(String s) {
    byte[] b = new byte[s.length()/2];
    for(int i = 0; i < b.length; i++) {
      b[i] = (byte) Integer.parseInt(s.substring(i*2,(i+1)*2),16); }
    return b;
  }
  public String byte2str(byte[] b) {
    String s = "";
    for(int i = 0; i < b.length; i ++) {
      char b_i = (char)b[i];
      String g = Integer.toHexString( b_i & 0x00ff );
      s += (g.length() == 1 ? "0" : "") + g; }
    return s;
  }

  public void run() {
    try {
    //get server's public key
    serverPubKey = SecurityUtil.getPublicKey("datos_asim_srv.pub");

    //connect to server
    serverConnect("localhost",4030);
    sendStr("connection start","SECURE INIT");

    //get G, P, G^x, signature from server
    String g_str = rcvStr("g");
    String p_str = rcvStr("p");
    String g2x_str = rcvStr("g2x");
    String sig_str = rcvStr("signature");
    BigInteger g = new BigInteger(g_str);
    BigInteger p = new BigInteger(p_str);
    BigInteger g2x = new BigInteger(g2x_str);
    byte[] sig_by = str2byte(sig_str);

    //verify signature
    String m = g_str+","+p_str+","+g2x_str;
    boolean sigVerified = SecurityUtil.verifySig(serverPubKey,sig_by,m);
    authenticate(sigVerified);
    if(!sigVerified) {
      return;
    }

    //choose y, send g^y
    int y_int = Math.abs(new SecureRandom().nextInt());
    BigInteger y = BigInteger.valueOf(Long.valueOf(y_int));
    sendStr("g2y",getG2Y(g,y,p).toString());

    //compute g^{xy}, derive symmetric keys from it
    BigInteger g2xy = g2x.modPow(y,p);
    String g2xy_str = g2xy.toString();
    SecretKey encKey = SecurityUtil.makeSecretKey(g2xy_str,0,32);
    SecretKey authKey = SecurityUtil.makeSecretKey(g2xy_str,32,32);

    //create the request
    int req = 9999999;
    byte[] req_by = Integer.toString(req).getBytes();
    //generate the nonce
    byte[] reqIv_by = SecurityUtil.generateIVBytes();
    String reqIv_str = byte2str(reqIv_by);
    IvParameterSpec reqIv = new IvParameterSpec(reqIv_by);
    //encrypt request with encryption key and iv
    byte[] encReq_by = SecurityUtil.symmEncrypt(req_by,encKey,reqIv);
    String encReq_str = byte2str(encReq_by);
    //hash-mac request with authenticaation key
    byte[] clientTag_by = SecurityUtil.hmac(req_by,authKey);
    String clientTag_str = byte2str(clientTag_by);

    //send encrypted request, hmac tag, nonce
    sendStr("encrypted request",encReq_str);
    sendStr("hmac tag",clientTag_str);
    sendStr("iv",reqIv_str);

    //get server responses
    String okay = rcvStr("client hmac tag verified");
    String encResp_str = rcvStr("encrypted response");
    String serverTag_str = rcvStr("server hmac tag");
    String respIv_str = rcvStr("iv");
    IvParameterSpec respIv = new IvParameterSpec(str2byte(respIv_str));
    byte[] serverTag_by = str2byte(serverTag_str);

    //decrypt server's message
    byte[] resp_by = SecurityUtil.symmDecrypt(str2byte(encResp_str),encKey,respIv);
    int resp = Integer.parseInt(new String(resp_by,StandardCharsets.UTF_8));
    //System.out.println("--- decrypted server response: " + resp);

    //verify server's HMAC tag
    authenticate(SecurityUtil.verifyTag(resp_by,authKey,serverTag_by));

    //exit
    socket.close();
    } catch(Exception e) {
      e.printStackTrace();
    }
  }
}
