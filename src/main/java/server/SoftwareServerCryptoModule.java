package server;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.milagro.amcl.AES;
import org.apache.milagro.amcl.BLS461.*;
import org.apache.milagro.amcl.HASH512;
import org.apache.milagro.amcl.RAND;


import server.interfaces.ServerCryptoModule;


public class SoftwareServerCryptoModule implements ServerCryptoModule {

	private BIG secret;
	//private final FP12 generator = org.apache.milagro.amcl.BLS461.PAIR.fexp(PAIR.ate(ECP2.generator(),ECP.generator()));
	private Random rand;
	private RAND rng = new RAND();
	private byte[] key;
	private byte[] iv;
	AES a=new AES();

	
	
	public SoftwareServerCryptoModule(Random random, byte[] key, byte[] iv) {

		this.rand = random;
		rng.seed(0, null); //TODO
		this.key = Arrays.copyOf(key,32);
		this.iv = Arrays.copyOf(iv,16);
		this.a.init(AES.CTR16,32,key,iv);
	}


	public void setupServer(BIG secret){
		this.secret = secret;
	}


	@Override
	public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature) throws Exception {
		Signature sig = null;
		if("RSA".equals(publicKey.getAlgorithm())) {
			sig = Signature.getInstance("SHA256withRSA");
		} else {
			sig = Signature.getInstance("SHA256withECDSA");
		}
		sig.initVerify(publicKey);
		for(byte[] bytes: input) {
			sig.update(bytes);
		}
		return sig.verify(signature);
	}

	@Override
	public byte[] getBytes(int noOfBytes) {
		byte[] bytes = new byte[noOfBytes];
		rand.nextBytes(bytes);
		return bytes;
	}
	
	@Override
	public ECP hashToECPElement(byte[] input) {
		HASH512 h = new HASH512();
		h.process_array(input);
		byte[] bytes = h.hash();
		BIG big1 = BIG.fromBytes(bytes);
		return ECP.generator().mul(big1);
	}
	
/*	private BIG hashToBIG(byte[] input, String ssid) {
		HASH512 h = new HASH512();
		h.process_array(input);
		h.process_array(ssid.getBytes());
		byte[] bytes = h.hash();

		return BIG.fromBytes(bytes);
	}*/

	@Override
	public byte[] hash(List<byte[]> input) {
		HASH512 h = new HASH512();
		for(byte[] b: input) {
			h.process_array(b);
		}
		return h.hash();
	}

	@Override
	public byte[] constructNonce(String username, long salt) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(salt);
		List<byte[]> toHash = new ArrayList<>();
		toHash.add(buffer.array());
		toHash.add(username.getBytes());
		return hash(toHash);
	}

	@Override
	public byte[] userSpecificKey(byte[] input)
	{
		BIG sec = this.secret;
		int length = 64;
		byte[] userKey = new byte[length];
		byte[] thisBlock;
		ByteBuffer buffer = ByteBuffer.allocate(length);
		buffer.putLong(sec.hashCode());
		buffer.put(input);
		byte[] block = Arrays.copyOf(buffer.array(),length);
		for(int i=0;i<(length/16);i++)
		{
			thisBlock = Arrays.copyOfRange(block,16*i,16*i+16);
			this.a.encrypt(thisBlock);
			for(int j=0;j<16;j++)
				userKey[16*i+j]=thisBlock[j];
			a.reset(AES.CTR16,this.iv);
		}
		return userKey;

	}

	@Override
	public BIG getRandomNumber() {
		return BIG.random(rng);
	}


	@Override
	public FP12 hashAndPair(BIG osk, ECP2 x, ECP com) {

		FP12 y;
		if(com!=null)
			y = PAIR.ate(x, com);
		else
			y = PAIR.ate(x,ECP.generator());


		return y.pow(osk);
	}
}
