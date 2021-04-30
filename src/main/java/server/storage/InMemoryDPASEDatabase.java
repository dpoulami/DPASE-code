package server.storage;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import server.interfaces.DPASEDatabase;

/**
 * In memory implementation of the PestoDatabase.
 * The implementation contains two hashmaps:
 * -A map of User and their UserData
 * -A map of the partial server signatures on user public keys (used for registration)
 *
 */

public class InMemoryDPASEDatabase implements DPASEDatabase{

	private final Map<String, UserData> users;
//	private final Map<String, List<byte[]>> partialServerSignatures;

	public InMemoryDPASEDatabase(){
		this.users = new HashMap<>();
//		this.partialServerSignatures = new HashMap<>();
	}

	public static InMemoryDPASEDatabase getInstance(){
		//TODO Change to singleton when servers are run in different instances (expected behaviour)


		return new InMemoryDPASEDatabase();
	}


	@Override
	public void addUser(String username, PublicKey key, long salt) {
		UserData user = new UserData(key, salt);
		this.users.put(username, user); //associating the key(username) with specific value(userData)
	}

/*

	@Override
	public Map<String, Attribute> getAttributes(String username) {
		return this.users.get(username).getAttributes();
	}

	@Override
	public void addAttributes(String username, Map<String, Attribute> attributes) {
		this.users.get(username).getAttributes().putAll(attributes);
	}
*/

	@Override
	public boolean hasUser(String username) {
		return this.users.containsKey(username);
	}

	@Override
	public PublicKey getUserKey(String username) {
		try {
			return this.users.get(username).getPublicKey();
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public long getLastSalt(String username) {
		return this.users.get(username).getSalt();
	}

	@Override
	public void setSalt(String username, long salt) {
		this.users.get(username).setSalt(salt);
	}

}
