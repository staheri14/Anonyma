import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.BigIntegers;

public class Invitee {

	Server server;
	BigInteger[] Token; 
	Shamir_Scheme shamir;
	ElGamal gamal;
	BigInteger d;
	
	/**
	 * Collect the invitations into one invitation letter
	 * @param Invitations[]
	 * @param ek
	 * @param Token
	 * @return
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public Invitation Icoll(Invitation[] Inv, Key ek, BigInteger[] Token) 
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidCipherTextException, IOException, InvalidAlgorithmParameterException {
		server = Server.getInstance();
		shamir = new Shamir_Scheme();
		gamal = new ElGamal();
		
		SecureRandom random = new SecureRandom();
		BigInteger p = server.getP();
		BigInteger q = server.getQ();
		BigInteger w = Token[2];
		d = new BigInteger(q.bitLength(), random).mod(q);
		
		int[] IDs = new int[Inv.length];
		for(int i = 0; i < Inv.length; i++) {
			IDs[i] = Inv[i].getId();
		}		
		
		BigInteger [] B = new BigInteger[Inv.length];
		for(int i = 0; i < B.length; i++) {
			B[i] = shamir.lagrangeCoefficients(IDs, i, q);
		}		
				
		BigInteger T = w.modPow(d, p); 
		byte[] ed = gamal.encrypt(BigIntegers.asUnsignedByteArray(T), ek);
		for(int i = 0; i < Inv.length; i++) {			
			T = T.multiply((Inv[i].getT()).modPow(B[i], p));
			ed = gamal.multiply(ed, gamal.pow(Inv[i].getEd(), B[i], server.ek), server.ek);
		}
		
		return new Invitation(T.mod(p), ed, null);
				
	}
	
}
