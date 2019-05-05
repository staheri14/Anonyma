import java.math.BigInteger;

public class POICwitness {
    private BigInteger secretshare;
    private BigInteger encRand;
    private BigInteger delta;


    public POICwitness(BigInteger secretshare, BigInteger encRand, BigInteger delta) {
        this.secretshare = secretshare;
        this.encRand = encRand;
        this.delta = delta;
    }

    public BigInteger getSecretshare() {
        return secretshare;
    }

    public BigInteger getEncRand() {
        return encRand;
    }

    public BigInteger getDelta() {
        return delta;
    }
}
