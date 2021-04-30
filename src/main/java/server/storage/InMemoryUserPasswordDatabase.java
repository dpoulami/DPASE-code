/*
package eu.olympus.server.storage;

import java.util.HashMap;
import java.util.Map;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.UserPasswordDatabase;

*/
/**
 * In memory implementation of the UserPasswordDatabase.
 * The implementation contains 3 hashmaps:
 * -A map of users and their attributes
 * -A map of users and their hashed passwords 
 * -A map of users and their salts
 *//*

public class InMemoryUserPasswordDatabase implements UserPasswordDatabase{

	private Map<String, String> pwdb;
	private Map<String, String> saltdb;
	private Map<String, Map<String, Attribute>> attributeMap;
	
	public InMemoryUserPasswordDatabase(){
		this.pwdb = new HashMap<String, String>();
		this.saltdb = new HashMap<String, String>();
		this.attributeMap = new HashMap<String, Map<String, Attribute>>();
	}

	@Override
	public void addUser(String username, String salt, String password) {
		this.pwdb.put(username, password);
		this.saltdb.put(username, salt);
		this.attributeMap.put(username, new HashMap<String, Attribute>());
	}

	@Override
	public String getPassword(String username) {
		return this.pwdb.get(username);
	}
	
	@Override
	public String getSalt(String username) {
		return this.saltdb.get(username);
	}

	@Override
	public Map<String, Attribute> getAttributes(String username) {
		return this.attributeMap.get(username);
	}

	@Override
	public void addAttributes(String username, Map<String, Attribute> attributes) {
		this.attributeMap.get(username).putAll(attributes);
	}
	
	@Override
	public boolean hasUser(String username) {
		
		return this.pwdb.containsKey(username);
	}


	
}
*/
