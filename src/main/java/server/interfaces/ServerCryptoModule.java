package server.interfaces;

import util.CommonCrypto;
import org.apache.milagro.amcl.BLS461.*;

public interface ServerCryptoModule extends CommonCrypto {

	public ECP hashToECPElement(byte[] input);

	public FP12 hashAndPair(BIG osk, ECP2 x, ECP com);

	public void setupServer(BIG secret);

	public byte[] userSpecificKey(byte[] b);


}
