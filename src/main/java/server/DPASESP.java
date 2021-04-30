package server;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.apache.milagro.amcl.BLS461.*;
import model.OPRFResponse;
import server.interfaces.ServerCryptoModule;
import server.interfaces.Storage;


public class DPASESP{

	private DPASEAuthenticationHandler authenticationHandler;
	private ServerCryptoModule cryptoModule;


	public DPASESP(Storage database, int id) throws Exception{
		if (database != null) {
			int i;
			Random r = new SecureRandom();
			String s = r.toString();
			byte[] key= Arrays.copyOf(s.getBytes(),32);
			byte[] iv = new byte[16];
			for (i=0;i<16;i++) iv[i]=(byte)i;
			cryptoModule = new SoftwareServerCryptoModule(new SecureRandom(),key,iv);
			authenticationHandler = new DPASEAuthenticationHandler(database, id, cryptoModule);
		}
	}


	public void setup(BIG secret) {
		try {
			cryptoModule.setupServer(secret);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public OPRFResponse performOPRF(String ssid, String username, ECP2 x, ECP com) throws NoSuchAlgorithmException {
		return authenticationHandler.performOPRF(ssid, username, x, com);
	}

	public Boolean finishRegistration(String username, PublicKey publicKey, long salt) throws Exception {
		return authenticationHandler.finishRegistration(username, publicKey, salt);
	}

	public boolean authenticate(String username, long salt, byte[] signature) throws Exception {
		boolean authenticated = authenticationHandler.authenticate(username, salt, signature);
		if(authenticated) {
			try{
				return true;
			} catch(Exception e) {
				e.printStackTrace();
				return false;
			}
		}
		return false;
	}

}
