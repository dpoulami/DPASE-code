package server.interfaces;

//import eu.olympus.model.Attribute;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

/**
 * Interface for storage used by the DPASE implementation
 * 
 */
public interface DPASEDatabase extends Storage{

	/**
	 * Add a user to the database.
	 * @param username Username of the user
	 * @param key The public key (derived from the OPRF), used to authenticate the user 
	 * @param salt A running number used to generate nonces.
	 */
	public void addUser(String username, PublicKey key, long salt);
	
	/**
	 * Get the public key for a user.
	 * @param username The username of the user for to do the lookup.
	 * @return The public key belonging to the user
	 */
	public PublicKey getUserKey(String username);
	
	/**
	 * Store a partial signature.
	 * The partial signature is only used during the registration.
	 * @param username The username of the user owning the signature
	 * @param signature The signature to store
	 */
//	public void addPartialSignature(String username, byte[] signature);
	
	/**
	 * Get all partial signatures belonging to a user.
	 * @param username The username to lookup
	 * @return A List of partial signatures
	 */
//	public List<byte[]> getPartialSignatures(String username);
	
	/**
	 * Remove all partial signatures belonging to a user.
	 * @param username The username of the owner of the signatures to delete
	 */
//	public void deletePartialSignatures(String username);

	/**
	 * Get the last salt used by the user.
	 * @param username The username of the user
	 * @return The last used salt.
	 */
	public long getLastSalt(String username);
	
	/**
	 * Store a salt belonging to a user.
	 * @param username The username of the user
	 * @param salt The salt to store
	 */
	public void setSalt(String username, long salt);

}
