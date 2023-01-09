package seguridad20222_servidor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SrvThread extends Thread{

	// constantes
	
	// Atributos
	private Socket sc = null;
	private int id;
	private String dlg;	
	private BigInteger p;
	private BigInteger g;
	private SecurityFunctions f;	
	private int mod;

	SrvThread (Socket csP, int idP, int modP) {
		sc = csP;
		dlg = new String("concurrent server " + idP + ": ");
		id = idP;
		/*
		 *  Concurrent servers run in one of three modes: 
		 *  0-ERROR 
		 *  1-OK_ERROR 
		 *  2-OK_OK 
		 */
		mod = modP;
	}
	
	public void run() {
		
		boolean exito = true;
		String linea;
	    System.out.println(dlg + "starting.");
	    f = new SecurityFunctions();
	    
		if (mod==0) {
			System.out.println("Running test 0.");
		} else if (mod==1){
			System.out.println("Running test 1.");
		} else if (mod==2) {
			System.out.println("Running test 2.");
		}

	    try {

			PrivateKey privadaServidor = f.read_kmin("datos_asim_srv.pri",dlg);
			PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub",dlg);
			PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
			BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));
				    	
			linea = dc.readLine();
			System.out.println(dlg + "reading request: " + linea);
    		
    		generateGandP();
			SecureRandom r = new SecureRandom();
			int x = Math.abs(r.nextInt());
			
    		Long longx = Long.valueOf(x);
    		BigInteger bix = BigInteger.valueOf(longx);
    		BigInteger valor_comun = G2X(g,bix,p);
    		String str_valor_comun = valor_comun.toString();
    		System.out.println(dlg + "G2X: "+str_valor_comun);
    		    		
    		// sending G, P y G^x
    		ac.println(g.toString());
    		ac.println(p.toString());
    		ac.println(str_valor_comun);
    		
    		if (mod==0) {
    			exito = opt0(str_valor_comun, ac, dc);
    		} else if (mod==1){
    			exito = opt1( str_valor_comun, ac, dc, bix, privadaServidor);
    		} else if (mod==2) {
    			exito = opt2( str_valor_comun, ac, dc, bix, privadaServidor);
			}
	        if (exito)
	        	System.out.println(dlg + "Finishing test: passed.");		
	        else
	        	System.out.println(dlg + "Finishing test: failed.");
	        sc.close();
	    } catch (Exception e) { e.printStackTrace(); }

	}
	
	
	private boolean opt0(String str_valor_comun, PrintWriter ac, BufferedReader dc) throws Exception {
		// option 0: signing verification should not check
		// we generate the error on purpose
		String linea;
		String msj = g.toString()+","+p.toString()+","+str_valor_comun;
		PrivateKey privadaError = gprivate_rsa();
		//
		// ERROR: -> signing with a different private key
		//
		byte[] byte_authentication = f.sign(privadaError, msj);
		String str_authentication = byte2str(byte_authentication);
		ac.println(str_authentication);
		linea = dc.readLine();
		boolean exito;
		if (linea.compareTo("ERROR")==0) {
			System.out.println("==========> Test 0: passed (Server sends wrong signature).");
			exito = true;
		} else {
			System.out.println("==========> Test 0: failed (Server sends wrong signature).");
			exito = false;
		}
		return exito;
	}
	
	private boolean opt1(String str_valor_comun, PrintWriter ac, BufferedReader dc, 
			BigInteger bix, PrivateKey privadaServidor) throws Exception {
		String linea;
		// option 1: signing verification should be ok but
		// answer integrity check should fail
		// we generate the error on purpose
		boolean exito = true;
		String msj = g.toString()+","+p.toString()+","+str_valor_comun;
		byte[] byte_authentication = f.sign(privadaServidor, msj);
		String str_authentication = byte2str(byte_authentication);
		ac.println(str_authentication);
		linea = dc.readLine();
		
		if (linea.compareTo("ERROR")==0) {
			exito = false;
			System.out.println("==========> Test 1a: failed (Server sends right signature).");
			
		} else if (linea.compareTo("OK")==0) {
			// Signature is right; server should receive "OK"
			System.out.println("==========> Test 1a: passed (Server sends right signature).");
    		// receiving G^y
    		linea = dc.readLine();
    		
    		// computing (G^y)^x mod N
    		BigInteger g2y = new BigInteger(linea);
    		BigInteger llave_maestra = calcular_llave_maestra(g2y,bix,p);
    		String str_llave = llave_maestra.toString();
    		System.out.println(dlg + " llave maestra: " + str_llave);
    		
    		// generating symmetric key
			SecretKey sk_srv = f.csk1(str_llave);
			SecretKey sk_mac = f.csk2(str_llave);
			
			String str_consulta = dc.readLine();
			String str_mac = dc.readLine();
			String str_iv1 = dc.readLine();
			byte[] byte_consulta = str2byte(str_consulta);
			byte[] byte_mac = str2byte(str_mac);
			
			// Espera consulta del cliente
			// debe responder con el número + 1

			byte[] iv1 = str2byte(str_iv1);
			IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
	    	byte[] descifrado = f.sdec(byte_consulta, sk_srv,ivSpec1);
	    	boolean verificar = f.checkInt(descifrado, sk_mac, byte_mac);
			System.out.println(dlg + "Integrity check:" + verificar);    		

	    	if (verificar) {
	    		System.out.println("==========> Test 1b: passed (Client sends matching query and MAC).");
	    		
	        	String str_original = new String(descifrado, StandardCharsets.UTF_8);
	        	int valor = Integer.parseInt(str_original) + 1;
	    		System.out.println(dlg + "Query answer:" + valor);
	        	String str_valor = Integer.toString(valor);
	        	byte[] byte_valor = str_valor.getBytes();
        		//
        		// ERROR: -> generating MAC with a wrong key
        		//
	        	String str_llave2 = String.valueOf(str_llave);
	        	str_llave2+="1";
	        	System.out.println(str_llave);
	        	System.out.println("vs");
	        	System.out.println(str_llave2);
				byte[] iv2 = generateIvBytes();
	        	String str_iv2 = byte2str(iv2);
				IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
	        	SecretKey sk_srv2 = f.csk1(str_llave2);
	        	byte[] rta_consulta = f.senc(byte_valor, sk_srv, ivSpec2, "Servidor");
	        	byte [] rta_mac = f.hmac(byte_valor, sk_srv2);
	        	String m1 = byte2str(rta_consulta);
	        	String m2 = byte2str(rta_mac);
	        	ac.println("OK");
	        	ac.println(m1);
	        	ac.println(m2);
	    		ac.println(str_iv2);
	        	
	        	linea = dc.readLine();
    			if (linea.compareTo("ERROR")==0) {
    				// MAC is not right, Client should send "ERROR".
    				System.out.println("==========> Test 1c: passed (server sends not matching query and MAC).");
    			} else if (linea.compareTo("OK")==0) {
    				System.out.println("==========> Test 1c: failed (server sends not matching query and MAC).");
    				exito = false;
    			}
	    	} else {
	    		// In this case, a client sends query and MAC that do not check
	    		String mensaje = "ERROR";
	        	ac.println(mensaje);
	        	System.out.println("==========> Test 1b: failed (Client sends not matching query and MAC).");
				exito = false;
	    	}
		} 
		return exito;
	}
	
	private boolean opt2 (String str_valor_comun, PrintWriter ac, BufferedReader dc, 
			BigInteger bix, PrivateKey privadaServidor) throws Exception {
		String linea;
		// option 2: signing verification should check and
		// answer integrity should also check
		boolean exito = true;
		String msj = g.toString()+","+p.toString()+","+str_valor_comun;
		byte[] byte_authentication = f.sign(privadaServidor, msj);
		String str_authentication = byte2str(byte_authentication);
		ac.println(str_authentication);
		linea = dc.readLine();
		
		if (linea.compareTo("ERROR")==0) {
			System.out.println("==========> Test 2a: failed (Server sends right signature).");
			exito = false;
			
		} else if (linea.compareTo("OK")==0) {
			System.out.println("==========> Test 2a: passed (Server sends right signature).");

    		// receiving G^y
    		linea = dc.readLine();
    		
    		// computing (G^y)^x mod N
    		BigInteger g2y = new BigInteger(linea);
    		BigInteger llave_maestra = calcular_llave_maestra(g2y,bix,p);
    		String str_llave = llave_maestra.toString();
    		System.out.println(dlg + " llave maestra: " + str_llave);
    		
    		// generating symmetric key
			SecretKey sk_srv = f.csk1(str_llave);
			SecretKey sk_mac = f.csk2(str_llave);
			
			String str_consulta = dc.readLine();
			String str_mac = dc.readLine();
			String str_iv1 = dc.readLine();
			byte[] byte_consulta = str2byte(str_consulta);
			byte[] byte_mac = str2byte(str_mac);
			
			byte[] iv1 = str2byte(str_iv1);
			IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
	    	byte[] descifrado = f.sdec(byte_consulta, sk_srv,ivSpec1);
	    	boolean verificar = f.checkInt(descifrado, sk_mac, byte_mac);
			System.out.println(dlg + "Integrity check:" + verificar);    		

	    	if (verificar) {
	    		System.out.println("==========> Test 2b: passed (Client sends matching query and MAC).");

	        	String str_original = new String(descifrado, StandardCharsets.UTF_8);
	        	int valor = Integer.parseInt(str_original) + 1;
	    		System.out.println(dlg + "Query answer:" + valor);
	        	String str_valor = Integer.toString(valor);
	        	byte[] byte_valor = str_valor.getBytes();
	        	
				byte[] iv2 = generateIvBytes();
	        	String str_iv2 = byte2str(iv2);
				IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);

	        	byte[] rta_consulta = f.senc(byte_valor, sk_srv,ivSpec2, "Servidor");
	        	byte [] rta_mac = f.hmac(byte_valor, sk_mac);
	        	String m1 = byte2str(rta_consulta);
	        	String m2 = byte2str(rta_mac);
	        	ac.println("OK");
	        	ac.println(m1);
	        	ac.println(m2);
	        	ac.println(str_iv2);
	        	
	        	linea = dc.readLine();
    			if (linea.compareTo("OK")==0) {
    				System.out.println("==========> Test 2c: passed (server sends matching query and MAC).");
    			} else if (linea.compareTo("ERROR")==0) {
    				System.out.println("==========> Test 2c: failed (server sends matching query and MAC).");
    				exito = false;
    			}
	        	
	    	} else {
	    		// In this case, a client send query and MAC that do not check
	    		String mensaje = "ERROR";
	        	ac.println(mensaje);
	    		System.out.println("==========> Test 2b: failed (Client sends not matching query and MAC).");
				exito = false;
	    	}
		} 
		return exito;
	}
	
	public byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
	
	private void generateGandP(){
    	int bitLength = 1024; 
        SecureRandom rnd = new SecureRandom();
        p = BigInteger.probablePrime(bitLength, rnd);
        g = BigInteger.probablePrime(bitLength, rnd);   

        String txtP = p.toString();
        String txtG = g.toString();
        System.out.println(dlg + "P: " +txtP);
        System.out.println(dlg + "G: " +txtG);
	}
	
	private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
	
	private BigInteger G2X(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}
	
	private BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}
	
	private PrivateKey gprivate_rsa() throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(1024, new SecureRandom());
		KeyPair kp = kpGen.genKeyPair();
		return kp.getPrivate();
	}
	
}

