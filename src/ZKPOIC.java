import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class ZKPOIC {

    public static POICproof prove(Invitation invitation, Token token, POICwitness wit) throws Exception
    {

        BigInteger si=wit.getSecretshare();
        BigInteger r=wit.getEncRand();
        BigInteger di=wit.getDelta();

        Server server = Server.getInstance();
        ElGamalPublicKey pub = (ElGamalPublicKey) ElGamal.pubKey;
        BigInteger h = pub.getY();
        BigInteger p=server.getP();
        BigInteger q=server.getQ();
        BigInteger g=server.getG();
        BigInteger w = token.getOmega();



        SecureRandom random = new SecureRandom();

        BigInteger sprime = new BigInteger(q.bitLength(), random).mod(q);
        BigInteger dprime = new BigInteger(q.bitLength(), random).mod(q);
        BigInteger rprime = new BigInteger(q.bitLength(), random).mod(q);


        BigInteger A=g.modPow(sprime,p);
        BigInteger B=(w.modPow(dprime, p).multiply(h.modPow(rprime,p))).mod(p);
        BigInteger C=w.modPow(sprime.add(dprime), p);

        BigInteger e=hash(A,B,B).mod(q);

        BigInteger Z1=(sprime.add(e.multiply(si))).mod(q);
        BigInteger Z2=(dprime.add(e.multiply(di))).mod(q);
        BigInteger Z3=(rprime.add(e.multiply(r))).mod(q);

        POICproof proof=new POICproof(A,B,C,Z1,Z2,Z3,e);
        return proof;
    }

    static BigInteger  hash(BigInteger A, BigInteger B, BigInteger C) throws  Exception
    {
        // Static getInstance method is called with hashing SHA
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method called
        // to calculate message digest of an input
        // and return array of byte
        byte [] Abarray=A.toByteArray();
        byte [] Bbarray=B.toByteArray();
        byte [] Cbarray=C.toByteArray();

        byte [] input= new byte[Abarray.length + Bbarray.length  + Cbarray.length ];
        System.arraycopy(Abarray, 0, input, 0, Abarray.length );
        System.arraycopy(Bbarray, 0, input, Abarray.length, Bbarray.length );
        System.arraycopy(Cbarray, 0, input, Abarray.length+Bbarray.length, Cbarray.length );
        byte[] messageDigest = md.digest(input);

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);
        return no;
    }

    public static Boolean verify(Invitation invitation, Token token, BigInteger gammai, POICproof proof) throws Exception
    {
        Server server = Server.getInstance();
        ElGamalPublicKey pub = (ElGamalPublicKey) ElGamal.pubKey;
        BigInteger h = pub.getY();
        BigInteger p=server.getP();
        BigInteger q=server.getQ();
        BigInteger g=server.getG();
        BigInteger w = token.getOmega();

        BigInteger C1r=(proof.getA().multiply(gammai.modPow(proof.getE(),p))).mod(p);
        BigInteger C1l=g.modPow(proof.getZ1(),p);

        proof.getB().multiply(invitation.getEd())

        return  true;
    }
}
