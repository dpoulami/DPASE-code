package server.interfaces;

//import eu.olympus.model.Attribute;

import java.util.Map;

/**
 * Generic interface for storage. 
 * The generic storage interface is used to manage user attributes
 * in a general fashion, independent of the choice of cryptographic
 * algorithms.
 * 
 */
public interface Storage {

	/**
	 * Checks if a the storage has an entry for the specified username.
	 * @param username The username 
	 * @return True if the username has an entry
	 */
	public boolean hasUser(String username);
	
	/**
	 * Get a map containing all attributes registered for a username.
	 * @param username The username of the attributes to fetch
	 * @return A map containing the attributes
	 */
//	public Map<String, Attribute> getAttributes(String username);
	
	/**
	 * Store a map of attributes to a specific user. 
	 * @param username The username of the user.
	 * @param attributes The attributes to store.
	 */
//	public void addAttributes(String username, Map<String, Attribute> attributes);
}
