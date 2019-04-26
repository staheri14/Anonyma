import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.BigIntegers;

public class Inviter {
	
	Server server;
	RSA_Signature rsa;
	ElGamal gamal;
	
	/**
	 * Generates the invitation for the invitee given the invitee's token
	 * @param Token
	 * @param s
	 * @param vk
	 * @param ek
	 * @return Invitation
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 */
	public Invitation Igen(BigInteger[] Token, SecretShare s, PublicKey vk, Key ek) 
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, 
			InvalidKeyException, SignatureException, InvalidCipherTextException, IOException {
		server = Server.getInstance();
		rsa = new RSA_Signature(server.getSignatureSecurityParameter());
		gamal = new ElGamal();
		String concat = Token[1].toString()+Token[2].toString();
		if(rsa.verify(new BigInteger(concat), Token[0].toByteArray(), vk)) {
			SecureRandom random = new SecureRandom();
			
			BigInteger di = new BigInteger(server.getQ().bitLength(), random).mod(server.getQ());

			BigInteger w = Token[2];
			BigInteger T = w.modPow((di.add(s.getShare())), server.getP());

			BigInteger m = w.modPow(di, server.getP());
			byte[] ed = gamal.encrypt(BigIntegers.asUnsignedByteArray(m), ek);
			Invitation invite = new Invitation(T, ed, s.getNumber());
			return invite;
		}
		return null;
	}

}
