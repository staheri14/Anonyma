import java.math.BigInteger;

public class Invitation {

	private BigInteger t;
	//private byte[] ed;
	private Integer j;
	private BigInteger[] ed;
	private  BigInteger di;
	
	Invitation(BigInteger t, BigInteger[] ed, Integer j, BigInteger d){
		this.t = t;
		this.ed = ed;
		this.j = j;
		this.di=d;
	}
	
	public BigInteger getT() {
		return this.t;
	}
	
	public BigInteger[] getEd() {
		return this.ed;
	}
	
	public Integer getId() {
		return this.j;
	}

	public BigInteger getDi() {
		return di;
	}
}
