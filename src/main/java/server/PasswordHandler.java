/*
package server;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import eu.olympus.model.IdentityProof;
import eu.olympus.model.PasswordAuthentication;
import eu.olympus.model.exceptions.ExistingUserException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.interfaces.AuthenticationHandler;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.interfaces.UserPasswordDatabase;

public class PasswordHandler extends AuthenticationHandler{

	private UserPasswordDatabase database;

	public PasswordHandler(Storage database) throws Exception {
		super(database);
		if(database instanceof UserPasswordDatabase) {
			this.database = (UserPasswordDatabase) database;
		} else {
			throw new Exception("Not a valid database");
		}
	}
	
	public void createUser(PasswordAuthentication creationData) throws UserCreationFailedException {
		if(this.database.hasUser(creationData.getUsername())) {
			throw new ExistingUserException();
		}

		SecureRandom random = new SecureRandom();
		byte[] saltBytes = new byte[16];
		random.nextBytes(saltBytes);
		
		String hash = "";
		String salt = "";

		// Switch to a better suited hash algorithm
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-512");
			md.update(saltBytes);

			byte[] hashBytes = md.digest(creationData.getPassword().getBytes(StandardCharsets.UTF_8));

			salt = Base64.getEncoder().encodeToString(saltBytes);
			hash = Base64.getEncoder().encodeToString(hashBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new UserCreationFailedException(e);
		}
		this.database.addUser(creationData.getUsername(), salt, hash);
	}


	public void createUserAndProveId(PasswordAuthentication creationData, IdentityProof idProof) throws UserCreationFailedException {
		createUser(creationData);
		addAttributes(creationData.getUsername(), idProof);
	}
	
	public boolean authenticate(PasswordAuthentication authenticationData) {
		String password = this.database.getPassword(authenticationData.getUsername());
		String salt = this.database.getSalt(authenticationData.getUsername());
		String candidate = authenticationData.getPassword();
		if(salt == null || password == null) {
			return false;
		}
		
		MessageDigest md;
		boolean valid = false;
		try {
			byte[] saltBytes = Base64.getDecoder().decode(salt);
			
			md = MessageDigest.getInstance("SHA-512");
			md.update(saltBytes);

			byte[] hashBytes = md.digest(candidate.getBytes(StandardCharsets.UTF_8));
			String hash = Base64.getEncoder().encodeToString(hashBytes);
			valid = password.equals(hash);
		} catch (NoSuchAlgorithmException e) {
			valid = false;
		}
		return valid;
	}
	
}
*/
