package server.interfaces;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//import eu.olympus.model.Attribute;
import model.IdentityProof;
import model.exceptions.UserCreationFailedException;

/**
 * Super class for authentication handling.
 * The sub classes may utilize the inherited methods
 * for adding attributes to an existing user or for
 * producing a set of claims fulfilling the specified policy.
 * 
 * A AuthenticationHandler subclass should provide
 * methods for creating/enrolling users and for authenticating
 * users. 
 *
 */
public class AuthenticationHandler {
	
	private Storage database;
	private List<IdentityProver> identityProvers;
	
	public AuthenticationHandler(Storage database) {
		this.database = database;
		this.identityProvers = new ArrayList<IdentityProver>();
	}

    public AuthenticationHandler() {

    }

    public void addIdentityProver(IdentityProver idProver) {
		this.identityProvers.add(idProver);		
	}
	
	/**
	 * Validates an identity proof and adds the set of
	 * contained attributes to an existing user.
	 * 
	 * This method assumes the user has already been authenticated. 
	 * @param username The user
	 * @param idProof The IdentityProof containing the attributes to add
	 * @throws UserCreationFailedException Thrown if the user does not exist.
	 */
/*	public void addAttributes(String username, IdentityProof idProof) throws UserCreationFailedException {
		if (this.database.hasUser(username)) {
			boolean proofIsValid = false;
			for(IdentityProver idProver : this.identityProvers) {
				proofIsValid = proofIsValid || idProver.isValid(idProof);
			}
			this.database.addAttributes(username, idProof.getAttributes());	
		} else {
			throw new UserCreationFailedException("User does not exist");
		}
	}*/

	/**
	 * Checks if a user can satisfy a policy and if so, produces
	 * a key-value mapping of the claims. 
	 * 
	 * Any policy that cannot be satisfied (e.g. the requested
	 * attribute does not exist for the user), will result in
	 * an exception.
	 * 
	 * @param username The user
	 * @param policy The policy to satisfy
	 * @return A map of the claims
	 * @throws Exception Thrown if the policy cannot be satisfied
	 */
/*	public Map<String, Attribute> validateAssertions(String username, List<String> policy) throws Exception{
		Map<String, Attribute> attributes = this.database.getAttributes(username);

		Map<String, Attribute> output = new HashMap<>();
		for(String key : policy) {
			Attribute attribute = attributes.get(key);
			if(attribute == null) {
				throw new Exception("User does not have the \"" + key + "\" attribute");
			}
			output.put(key, attribute);
		}
		return output;
	}*/

}
