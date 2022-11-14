package security_client;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;

class SecurityUtil {
  static long getName() {
    return Thread.currentThread().getId();
  }
  
  //read_kplus
  static PublicKey getPublicKey(String keyArchive) throws Exception {
    FileInputStream stream = new FileInputStream(keyArchive);
    byte[] bytes = new byte[(int)(new File(keyArchive)).length()];
    stream.read(bytes);
    stream.close();
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return factory.generatePublic(new X509EncodedKeySpec(bytes));
  }

  //checkSignature
 static boolean verifySig(PublicKey key, byte[] signature, String m) throws Exception {
    long time_start = System.nanoTime();
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(key);
    publicSignature.update(m.getBytes(StandardCharsets.UTF_8));
    boolean isVerified = publicSignature.verify(signature);
    long time_elapsed = System.nanoTime() - time_start;
    System.out.println(getName()+" (time) 0 signature verification : "+time_elapsed);
    return isVerified;
  }

  //csk1, use first half of seed/key
  //csk2, use 2nd half of seed/key
  static SecretKey makeSecretKey(String seed, int offset, int len) throws Exception {
    byte[] seed_bytes = seed.trim().getBytes(StandardCharsets.UTF_8);
    byte[] hash = MessageDigest.getInstance("SHA-512").digest(seed_bytes);
    byte[] hash_sub = new byte[len];
    for(int i = offset; i < offset+len; i++) {
      hash_sub[i - offset] = hash[i]; }
    SecretKey key = new SecretKeySpec(hash_sub,"AES");
    return key;
  }

  //senc
  static byte[] symmEncrypt(byte[] m, SecretKey k, IvParameterSpec iv) throws Exception {
    long time_start = System.nanoTime();
    Cipher encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encryptor.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] c = encryptor.doFinal(m);
    long time_elapsed = System.nanoTime() - time_start;
    System.out.println(getName()+" (time) 2 encrypted message      : "+time_elapsed);
    return c;
  }
  //sdec
  static byte[] symmDecrypt(byte[] c, SecretKey k, IvParameterSpec iv) throws Exception {
    //long time_start = System.nanoTime();
    Cipher encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encryptor.init(Cipher.DECRYPT_MODE, k, iv);
    byte[] m = encryptor.doFinal(c);
    //long time_elapsed = System.nanoTime() - time_start;
    //System.out.println("(time) decrypted message in: "+time_elapsed+" ns");
    return m;
  }

  //hmac
  static byte[] hmac(byte[] m, SecretKey k) throws Exception {
    long time_start = System.nanoTime();
    Mac macFxn = Mac.getInstance("HMACSHA256");
    macFxn.init(k);
    byte[] tag = macFxn.doFinal(m);
    long time_elapsed = System.nanoTime() - time_start;
    System.out.println(getName()+" (time) 3 hash-mac'd             : "+time_elapsed);
    return tag;
  }
  //checkInt
  static boolean verifyTag(byte[] m, SecretKey k, byte[] tag) throws Exception {
    Mac macFxn = Mac.getInstance("HMACSHA256");
    macFxn.init(k);
    byte[] tag_0 = macFxn.doFinal(m);
    if(tag_0.length != tag.length) {
      return false; }
    for(int i = 0; i < tag_0.length; i++) {
      if(tag_0[i] != tag[i]) {
        return false; }
    }
    return true;
  }

  //
  static byte[] generateIVBytes() {
    byte[] iv_bytes = new byte[16];
    new SecureRandom().nextBytes(iv_bytes);
    return iv_bytes;
  }
}
