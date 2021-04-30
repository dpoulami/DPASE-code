package server.interfaces;

import model.IdentityProof;

public interface IdentityProver {

	public boolean isValid(IdentityProof proof);
}
