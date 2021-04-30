package util;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;

import org.apache.milagro.amcl.BLS461.BIG;

/**
 * Interface for the crypto module used by both the
 * (DPASE) client and partial IdP.
 *
 * The implementations may be purely software based or use
 * various hardware augmentations, e.g. Hardware Security Modules,
 * Secure Enclaves, etc.
 *
 */
public interface CommonCrypto {

    /**
     * Construct a nonce given a username and a salt
     * @param username The username
     * @param salt The salt
     * @return A nonce
     */
    public byte[] constructNonce(String username, long salt);

    /**
     * Hashes a list of byte arrays.
     * @param bytes The byte arrays to hash
     * @return a byte array containing the hash
     */
    public byte[] hash(List<byte[]> bytes);

    /**
     * Get a number of random bytes.
     * @param noOfBytes The number of bytes to fetch
     * @return byte array containing the bytes
     */
    public byte[] getBytes(int noOfBytes);

    /**
     * Produce a RSA public used to validate signatures
     * of the vIdP
     * @return A RSA public key.
     * @throws Exception If the crypto module has not been initialized
     */
//    public PublicKey getStandardRSAkey() throws Exception;

    /**
     * The modulus of the RSA prime used by the vIdP signature scheme
     * @return
     */
//    public BigInteger getModulus();

    /**
     * Verify a signature
     * @param publicKey The public key to use for the verification
     * @param input The message to verify
     * @param signature The signature
     * @return true if the verification was successful
     * @throws  Exception If the required cryptographic algorithms
     * are not supported by the system or the key or signature is invalid.
     */
    public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature) throws Exception;

    /**
     * Produce a random number.
     * @return The random number
     */
    public BIG getRandomNumber();

}
