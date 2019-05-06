import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class ZKPOIC {

    /**
     *
     * @param invitation
     * @param token
     * @param wit
     * @return
     * @throws Exception
     */
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
        BigInteger B1=(w.modPow(dprime, p).multiply(h.modPow(rprime,p))).mod(p);
        BigInteger B2=(g.modPow(rprime,p)).mod(p);
        BigInteger C=w.modPow(sprime.add(dprime), p);

        BigInteger e=hash(A,B1,B2,C).mod(q);

        BigInteger Z1=(sprime.add(e.multiply(si))).mod(q);
        BigInteger Z2=(dprime.add(e.multiply(di))).mod(q);
        BigInteger Z3=(rprime.add(e.multiply(r))).mod(q);

        POICproof proof=new POICproof(A,B1,B2,C,Z1,Z2,Z3,e);
        return proof;
    }

    /**
     *
     * @param A
     * @param B1
     * @param B2
     * @param C
     * @return
     * @throws Exception
     */
    static BigInteger  hash(BigInteger A, BigInteger B1, BigInteger B2, BigInteger C) throws  Exception
    {
        // Static getInstance method is called with hashing SHA
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method called
        // to calculate message digest of an input
        // and return array of byte
        byte [] Abarray=A.toByteArray();
        byte [] B1barray=B1.toByteArray();
        byte [] B2barray=B2.toByteArray();
        byte [] Cbarray=C.toByteArray();

        byte [] input= new byte[Abarray.length + B1barray.length  + B2barray.length + Cbarray.length ];
        System.arraycopy(Abarray, 0, input, 0, Abarray.length );
        System.arraycopy(B1barray, 0, input, Abarray.length, B1barray.length );
        System.arraycopy(B2barray, 0, input, Abarray.length+B1barray.length, B2barray.length );
        System.arraycopy(Cbarray, 0, input, Abarray.length+B1barray.length+B2barray.length, Cbarray.length );
        byte[] messageDigest = md.digest(input);

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);
        return no;
    }

    /**
     *
      * @param invitation
     * @param token
     * @param gammai
     * @param proof
     * @return
     * @throws Exception
     */
    public static Boolean verify(Invitation invitation, Token token, BigInteger gammai, POICproof proof) throws Exception
    {
        Server server = Server.getInstance();
        ElGamalPublicKey pub = (ElGamalPublicKey) ElGamal.pubKey;
        BigInteger h = pub.getY();
        BigInteger p=server.getP();
        BigInteger q=server.getQ();
        BigInteger g=server.getG();
        BigInteger w = token.getOmega();
        BigInteger edi1= invitation.getEd()[0];
        BigInteger edi2= invitation.getEd()[1];
        BigInteger T= invitation.getT();

        BigInteger A=proof.getA();
        BigInteger B1=proof.getB1();
        BigInteger B2=proof.getB2();
        BigInteger C=proof.getC();
        BigInteger Z1=proof.getZ1();
        BigInteger Z2=proof.getZ2();
        BigInteger Z3=proof.getZ3();
        BigInteger E=proof.getE();




        BigInteger C1l=(A.multiply(gammai.modPow(E,p))).mod(p);
        BigInteger C1r=g.modPow(Z1,p);

        BigInteger C2l =(B1.multiply(edi1.modPow(E,p))).mod(p);
        BigInteger C2r =(w.modPow(Z2, p).multiply(h.modPow(Z3,p))).mod(p);


        BigInteger C3l=(B2.multiply(edi2.modPow(E,p))).mod(p);
        BigInteger C3r = g.modPow(Z3,p);

        BigInteger C4l= (((C.multiply(T.modPow(E,p))).mod(p)).multiply(h.modPow(Z3,p))).mod(p);
        BigInteger C4r= (((B1.multiply(edi1.modPow(E,p))).mod(p)).multiply(w.modPow(Z1,p))).mod(p);



        return  true;
    }
}
