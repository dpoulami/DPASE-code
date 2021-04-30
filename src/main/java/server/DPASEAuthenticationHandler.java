package server;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.milagro.amcl.BLS461.*;
import org.apache.milagro.amcl.BLS461.FP12;
import model.OPRFResponse;
import model.exceptions.ExistingUserException;
import model.exceptions.UserCreationFailedException;
import server.interfaces.AuthenticationHandler;
import server.interfaces.DPASEDatabase;
import server.interfaces.ServerCryptoModule;
import server.interfaces.Storage;

public class DPASEAuthenticationHandler extends AuthenticationHandler{

	private DPASEDatabase database;
	private ServerCryptoModule crypto;
	private static final long allowedTimeDiff = 10000;
	int id;

	public DPASEAuthenticationHandler(Storage database, int id, ServerCryptoModule crypto) throws Exception {
		super(database);
		if(database instanceof DPASEDatabase) {
			this.database = (DPASEDatabase) database;
		} else {
			throw new Exception("Not a valid database");
		}
		this.id = id;
		this.crypto = crypto;
	}

	public OPRFResponse performOPRF(String ssid, String username, ECP2 x, ECP com) {
		byte[] bytes = crypto.userSpecificKey(username.getBytes());
		BIG osk = BIG.fromBytes(Arrays.copyOf(bytes,58));
		long start_time = java.lang.System.nanoTime();
		FP12 y = crypto.hashAndPair(osk, x, com);   //y= (e(x,H2(com)))^osk_i
		long end_time = java.lang.System.nanoTime();
		OPRFResponse res = new OPRFResponse(y, ssid, end_time-start_time);   //ssid is transmitted into class OPRFResponse, res can call getSsid() to get ssid
		return res;
	}

	public Boolean finishRegistration(String username, PublicKey publicKey, long salt) throws Exception {
		if(this.database.hasUser(username)) {
			throw new ExistingUserException();
		}
		long currentTime = System.currentTimeMillis();
		if (salt > currentTime+allowedTimeDiff || salt < currentTime - allowedTimeDiff) {
			throw new UserCreationFailedException("Timestamp in request is either too new or too old");
		}

		this.database.addUser(username, publicKey, salt);
		return true;
	}


	public boolean authenticate(String username, long salt, byte[] signature) throws Exception {
		PublicKey userKey = this.database.getUserKey(username);
		if (userKey == null) {
			return false;
		}
//		if (!checkSalt(username, salt)) {
//			return false;
//		}
		byte[] nonce = crypto.constructNonce(username, salt);
		List<byte[]> list = new ArrayList<>(1);
		list.add(nonce);
		list.add(username.getBytes());
		boolean valid = crypto.verifySignature(userKey, list, signature);
		database.setSalt(username, salt);
		return (valid );
	}


	private boolean checkSalt(String username, long salt) {
		long oldSalt = this.database.getLastSalt(username);
		if (salt < oldSalt) {
			// Someone is reusing salt
			return false;
		}
		long currentTime = System.currentTimeMillis();
		if (salt > currentTime+allowedTimeDiff || salt < currentTime - allowedTimeDiff) {
			// The salt is too far from the current time
			return false;
		}
		return true;
	}

}
