import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class RSA_Signature {
	
	private int lambda;
	
	RSA_Signature(int lambda){
		this.lambda = lambda;
	}
	
	/**
	 * Generates the key pair of public and private for RSA
	 * @return keyPair
	 * 					pair of public and private key
	 * @throws NoSuchAlgorithmException 
	 */
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		//Size of the key:1024 The same library also supports 2048
    kpg.initialize(lambda, new SecureRandom());
    KeyPair keyPair = kpg.genKeyPair();
    
    return keyPair;
	}
	
	/**
	 * Signs the plainText with the privateKey given 
	 * @param plainText
	 * 					BigInteger to be signed
	 * @param privateKey
	 * 					Private key given by the signer 
	 * @return	signed plainText
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public byte[] sign(BigInteger plainText, PrivateKey privateKey) 
throws NoSuchAlgorithmException, InvalidKeyException, SignatureException  {
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(privateKey);
		sig.update(plainText.toByteArray());
		
		byte[] signature = sig.sign();
		return signature;
	}
	
	/**
	 * Verify the signed document
	 * @param plainText
	 * @param signature
	 * @param publicKey
	 * @return Acceptance on signature (True/False) 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public boolean verify(BigInteger plainText, byte[] signature, PublicKey publicKey) 
throws NoSuchAlgorithmException, InvalidKeyException, SignatureException  {
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(publicKey);
		sig.update(plainText.toByteArray());
		
		return sig.verify(signature);
	}

}
