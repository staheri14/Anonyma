import java.math.BigInteger;

/**
 * Created by stahe on 5/3/2019.
 */
public class Token {
    private byte[]  sign;
    private BigInteger index;
    private  BigInteger omega;

    public Token(byte[] sign, BigInteger index, BigInteger omega) {
        this.sign = sign;
        this.index = index;
        this.omega = omega;
    }

    public byte[] getSign() {
        return sign;
    }

    public BigInteger getIndex() {
        return index;
    }

    public BigInteger getOmega() {
        return omega;
    }
}
