import java.math.BigInteger;

public class Invitation {

	private BigInteger t;
	private byte[] ed;
	private Integer j;
	
	Invitation(BigInteger t, byte[] ed, Integer j){
		this.t = t;
		this.ed = ed;
		this.j = j;
	}
	
	public BigInteger getT() {
		return this.t;
	}
	
	public byte[] getEd() {
		return this.ed;
	}
	
	public Integer getId() {
		return this.j;
	}
}
