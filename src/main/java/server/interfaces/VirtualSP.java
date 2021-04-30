package server.interfaces;

import java.security.PublicKey;

/**
 * The external interface for the IdP. This should be implemented
 * as a REST interface by all partial IdPs.
 */
public interface VirtualSP {


	/**
	 * Return the  public key share for this IdP.
	 */
	public PublicKey getPublicKey();

}
