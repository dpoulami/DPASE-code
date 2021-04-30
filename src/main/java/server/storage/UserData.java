package server.storage;

import java.security.PublicKey;



public class UserData {

	private long salt;

	private final PublicKey publicKey;

	public UserData(PublicKey publicKey, long salt) {
		this.publicKey = publicKey;
		this.salt = salt;
	}

	public long getSalt() {
		return salt;
	}

	public void setSalt(long salt) {
		this.salt = salt;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
}
