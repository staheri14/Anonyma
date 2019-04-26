import java.math.BigInteger;

public class User {
	private final BigInteger j;
	private final SecretShare share;
	
	User(BigInteger j, SecretShare s){
		this.j = j;
		this.share = s;
	}
	public BigInteger getIndex() {
		return this.j;
	}
	
	public SecretShare getShare() {
		return this.share;
	}
	
}
