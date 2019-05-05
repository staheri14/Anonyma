import java.math.BigInteger;
import java.security.SecureRandom;

public class Shamir_Scheme {
	
	/**
	 * Generates the function of degree t-1 with f(0) = secret
	 * @param secret
	 * @param t
	 * 			Threshold
	 * @return function f
	 */
	public BigInteger[] functionGeneration(BigInteger secret, int t, BigInteger q) {
		//Creates the polynomial function at random
			final BigInteger[] coeff = new BigInteger[t];
			SecureRandom random = new SecureRandom();
			coeff[0] = secret;
			for(int i = 1; i < t; i++) {
				BigInteger ran;
				while (true) {
					ran = new BigInteger(1024, random);
					if(ran.compareTo(BigInteger.ZERO) > 0 && ran.compareTo(q) < 0) {
						break;
					}
				}
				coeff[i] = ran;
			}
			
			return coeff;
	}
	
	/**
	 * Generates a secret share for function f with id j
	 * @param function
	 * @param domain
	 * @param user id
	 * @return secret share for user j
	 */
	public SecretShare getShare(BigInteger[] f, BigInteger q, BigInteger j) {
		BigInteger acc = f[0];
		for(int exp = 1; exp < f.length; exp++) {	
			acc = acc.add(f[exp].multiply(BigInteger.valueOf(j.intValue()+1).pow(exp).mod(q))).mod(q);
		}
		acc = acc.mod(q);
		return new SecretShare(j.intValue()+1,acc);
	}

	/**
	 * Combines the shares into the secret (test purposes) 
	 * @param shares
	 * 		Shares used to combine secret
	 * @param p
	 * 		Prime 
	 * @return secret
	 * 		The combined secret
	 */
	public BigInteger combineSecret(final SecretShare[] shares, final BigInteger q) {
		BigInteger acc = BigInteger.ZERO;
		for(int i = 0; i < shares.length; i++) {
			BigInteger numerator = BigInteger.ONE;
			BigInteger denominator = BigInteger.ONE;
			
			for(int j = 0; j < shares.length; j++) {
				if(i == j) {
					continue;
				}
				
				int startPosition = shares[i].getNumber();
				int nextPosition = shares[j].getNumber();
				//numerator = ( numerator * -nextPosition ) % p
				numerator = numerator.multiply(BigInteger.valueOf(nextPosition).negate()).mod(q);
				//denominator = ( denominator * (startPosition - nextPosition) ) % p
				denominator = denominator.multiply(BigInteger.valueOf(startPosition - nextPosition)).mod(q);
			}
			
			BigInteger value = shares[i].getShare(); //recover share value
			BigInteger temp = value.multiply(numerator).multiply(denominator.modInverse(q));
			acc = q.add(acc).add(temp).mod(q); //acc = (p+acc+(value*numerator*-denominator%p))%p
			
		}
		
		System.out.println("The secret is: "+ acc + "\n");
		
		return acc;
	}

	/**
	 * Calculates the Lagrange coefficients for user i given the IDs of t users 
	 * @param IDs
	 * @param i
	 * @param q
	 * @return B[i]
	 */
	public BigInteger lagrangeCoefficients(int[] IDs, int i, BigInteger q) {
		BigInteger numerator = BigInteger.ONE;
		BigInteger denominator =  BigInteger.ONE;
		
		for(int j = 0; j < IDs.length; j++) {
			if(i == j) {
				continue;
			}
			
			int startPosition = IDs[i];
			int nextPosition = IDs[j];
			//numerator = ( numerator * -nextPosition ) % p
			numerator = numerator.multiply(BigInteger.valueOf(nextPosition).negate()).mod(q);
			//denominator = ( denominator * (startPosition - nextPosition) ) % p
			denominator = denominator.multiply(BigInteger.valueOf(startPosition - nextPosition)).mod(q);
		}
		
		BigInteger coeff = numerator.multiply(denominator.modInverse(q));
		
		return coeff;
	}
	
}
