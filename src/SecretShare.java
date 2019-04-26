import java.math.BigInteger;

/** Class representing a secret share */
public class SecretShare {
	
	private final int number;
	private final BigInteger share;
	
	/**
	 * Constructs new secret share
	 * @param number
	 * 					Share id 
	 * @param share
	 * 					Secret value share
	 */
	public SecretShare(final int number, final BigInteger share) {
		this.number = number;
		this.share = share;
	}
	
	/** @return Share id  */
	public int getNumber() {
		return number;
	}
	
	/** @return Share value  */
	public BigInteger getShare() {
		return share;
	}
	
	public String toString() {
		return "SecretShare [num = "+ number +", share = "+ share + "]";
	}

}
