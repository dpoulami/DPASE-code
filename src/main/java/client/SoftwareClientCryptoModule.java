package client;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.milagro.amcl.AES;
import org.apache.milagro.amcl.BLS461.ECP;
import org.apache.milagro.amcl.HASH512;
import org.apache.milagro.amcl.RAND;
import org.apache.milagro.amcl.BLS461.BIG;
import org.apache.milagro.amcl.BLS461.ECP2;
import org.apache.milagro.amcl.BLS461.ROM;

import client.interfaces.ClientCryptoModule;

public class SoftwareClientCryptoModule implements ClientCryptoModule{
    private Random rand;
    private RAND rng = new RAND();
    private byte[] key;
    private byte[] iv;
    AES a=new AES();

    public SoftwareClientCryptoModule(byte[] key, byte[] iv) {
        rng.seed(0, null);
        this.key = Arrays.copyOf(key,32);
        this.iv = Arrays.copyOf(iv,16);
        this.a.init(AES.CTR16,32,key,iv);
    }


    @Override
    public byte[] sign(PrivateKey privateKey, List<byte[]> message) throws Exception{
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        for(byte[] bytes : message) {
            sig.update(bytes);
        }
        return sig.sign();
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
    public KeyPair generateKeysFromBytes(byte[] bytes) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");   //Key generator algorithm: EC
        SecureRandom secure = SecureRandom.getInstance("SHA1PRNG"); //Seems to be the only alg? random number algorithm
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");  // parameter algorithm
        secure.setSeed(bytes);  //here bytes is Y
        keyGen.initialize(spec, secure);    //initialize keyGen with parameter and Y
        return keyGen.generateKeyPair();    //then generateKeyPair from keyGen
    }

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
    public BIG getRandomNumber() {
        return BIG.random(rng);
    }

    @Override
    public ECP2 hashAndMultiplyECP2(byte[] password, BIG r) {
        BIG order = new BIG(ROM.CURVE_Order);
        r.mod(order);
        ECP2 xMark = hashToECP2(password).mul(r);
        return xMark;
    }

    public ECP hashAndMultiplyECP(byte[] password, BIG r) {
        BIG order = new BIG(ROM.CURVE_Order);
        r.mod(order);
        ECP xMark = hashToECPElement(password).mul(r);
        return xMark;
    }

    private ECP2 hashToECP2(byte[] input) {
        HASH512 h = new HASH512();
        h.process_array(input);
        byte[] bytes = h.hash();
        BIG big1 = BIG.fromBytes(bytes);

        return ECP2.generator().mul(big1);
    }

    @Override
    public ECP hashToECPElement(byte[] input) {
        HASH512 h = new HASH512();
        h.process_array(input);
        byte[] bytes = h.hash();
        BIG big1 = BIG.fromBytes(bytes);
        return ECP.generator().mul(big1);
    }

    @Override
    public byte[] HPRG(byte[] seed, int length){
        byte[] block = Arrays.copyOf(seed,16);
        byte[] expandedKey = new byte[length];
        int times = length/16;
        int i;
        for(i=0;i<(length/16);i++)
        {
            block[15]= (byte) (block[15]+i);
            this.a.encrypt(block);
            for(int j=0;j<16;j++)
            expandedKey[16*i+j]=block[j];
        }
        return expandedKey;
    }

}
