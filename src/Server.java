import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.BigIntegers;

public class Server {
	List<User> users; 	//Not part of Inonymous, solely used for demonstration purposes
	RSA_Signature rsa;
	ElGamal gamal;
	Shamir_Scheme shamir;
	public Key ek;
	private Key dk;
	private Key sk;
	public Key vk;
	private BigInteger p;
	private BigInteger q;
	private BigInteger g; 
	private BigInteger[] f;
	private BigInteger S;
	private int t;
  private static Server instance;
  private int lambda = 1024;
  private int rsaLambda = 1024;
  
  /**
   * Creates an instance of the singleton Server class
   * @return Server instance
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidAlgorithmParameterException 
   */
  public static Server getInstance() 
throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    if (instance == null) {
      instance = new Server();
    }
    return instance;
  }

  /**
   * Private server constructor
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidAlgorithmParameterException 
   */
  private Server() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
  	t  = 5;
  	setUp(lambda, rsaLambda);
  }
	
  /**
   * Sets the security parameters, generates the function for SSS and generates the key pairs for encryption and signature
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidAlgorithmParameterException 
   */
	public void setUp(int lambda, int rsaLambda) 
throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException  {
		SecureRandom random = new SecureRandom();	
		
		do {
			p = new BigInteger("92961285174734881825998403645963911560015611795075805065458778189868420677518411263477540543939634976579264221188853682998107997370611821598919333708732163259097722182353873799043633864355448582689784071481377851105633745820340873246928099089758701115812065277435653724596581335374314988141688182923627354323");//new BigInteger(lambda, 256, random);;

			System.out.println("p "+p);
			q = generateQ(p);
		} while(q == null);
		g = generateG(p, q, random);

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		rsa = new RSA_Signature(rsaLambda);
		gamal = new ElGamal();
		shamir = new Shamir_Scheme();
		
		KeyPair elGamalKeyPair = gamal.generateKeyPair(p, g, random);
		ek = elGamalKeyPair.getPublic();
		dk = elGamalKeyPair.getPrivate();
		
		KeyPair RSAKeyPair = rsa.generateKeyPair();
		sk = RSAKeyPair.getPrivate();
		vk = RSAKeyPair.getPublic();
		
		S = new BigInteger(q.bitLength(), random).mod(q);
		f = shamir.functionGeneration(S, t, q);
		//users = generateUsers();
		users=new ArrayList<>();//initialize an empty list of users
	}
	
	/**
	 * Returns the generator g with cyclic group G of order q
	 * @param p
	 * @param q
	 * @param random
	 * @return g
	 */
	private BigInteger generateG(BigInteger p, BigInteger q, Random random) {
		BigInteger g; 
		do {
			BigInteger h = new BigInteger(1024, random).mod(p);
			g = h.modPow(p.subtract(BigInteger.ONE).divide(q), p);
		} while(g.equals(BigInteger.ONE) || g.equals(BigInteger.ZERO));
		return g;
	}
	
	/**
	 * Generates a prime q such that q|p-1
	 * @param p
	 * @return prime q
	 */
	private BigInteger generateQ(BigInteger p) {
		BigInteger q = (p.subtract(BigInteger.ONE)).divide(new BigInteger("2"));
		BigInteger r = (p.subtract(BigInteger.ONE)).mod(q);
		
		for(int i = 3; i < 10000; i++) {
			if(q.isProbablePrime(256) && r.equals(BigInteger.ZERO)) {
				return q;
			}
			q = (p.subtract(BigInteger.ONE)).divide(BigInteger.valueOf(i));
			r = p.subtract(BigInteger.ONE).mod(q);
		}
			return null;
	}
	
	/**
	 * Public token generation method for new invitees to access, calls the Tgen algorithm
	 * @return Token (n,j,w)
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 */
	public BigInteger[] TokenGeneration() 
throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		PrivateKey signKey = (PrivateKey) sk;
		BigInteger[]  token = Tgen(signKey, BigInteger.valueOf(users.size()));//takes the sign key and the total number of existing users
		return token;
	}
	
	/**
	 * Generates a token for each new invitee in the form Token(n,j,w)
	 * @param sk
	 * @param j
	 * @return Token (n,j,w)
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 */
	private BigInteger[] Tgen(PrivateKey sk, BigInteger j) 
throws InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		SecureRandom random = new SecureRandom();
		BigInteger r = (new BigInteger(1024, random)).mod(q);
		BigInteger w = g.modPow(r, p);
		String concat = j.toString()+w.toString();	
		byte[] signature = rsa.sign(new BigInteger(concat), sk);
		BigInteger n = new BigInteger(signature);
		
		BigInteger[] Token = {n,j,w};
		return Token;
	}
	
	/**
	 * Public verification method for invitees to access, calls the IVrfy algorithm
	 * @param InvLet
	 * @param Token
	 * @return accept/reject
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidCipherTextException
	 * @throws IOException
	 */
	public boolean verify(Invitation InvLet, BigInteger[] Token) 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidCipherTextException, IOException {
		return IVrfy(InvLet, Token, (PublicKey) vk, dk);
	}
	
	/**
	 * Verifies the authenticity of the invitations and accepts/rejects a new user
	 * @param InvLet
	 * @param Token
	 * @param verification_key
	 * @param decryption_key
	 * @return accept/reject
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidCipherTextException
	 * @throws IOException
	 */
	private boolean IVrfy(Invitation InvLet, BigInteger[] Token, PublicKey vk, Key dk) 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidCipherTextException, IOException {
		String concat = Token[1].toString()+Token[2].toString();
		if(rsa.verify(new BigInteger(concat), Token[0].toByteArray(), vk)) {
			//byte[] wDelta = gamal.decrypt(InvLet.getEd(), dk);

			BigInteger wS = Token[2].modPow(S, p);
			BigInteger T = new BigInteger(1, gamal.evaluate(InvLet.getEd(), gamal.encrypt(BigIntegers.asUnsignedByteArray(wS), ek), dk)).mod(p);
			
			if(T.equals(InvLet.getT())) {
				return true;
			} 
		}
		return false;
	}

	/**
	 * Registers a new user with id j
	 * @param j
	 * @return new User
	 */
	User Reg(BigInteger j) {
		SecretShare share = shamir.getShare(f, q, j);
		User user = new User(j, share);
		users.add(user); //add the user to the system
		return user;
	}

	/**
	 * Registers a new user with id j
	 * @param jint
	 * @return
	 */
	User Reg(int jint) {
		BigInteger j=new BigInteger(Integer.toString(jint));
		SecretShare share = shamir.getShare(f, q, j);
		User user = new User(j, share);
		users.add(user); //add the user to the system
		return user;
	}
	
	/**
	 * Generates a list of users for demo purposes
	 * @return List of registered users
	 */
	private List<User> generateUsers(){
		List<User> users = new ArrayList<>();
		for(int i = 0; i < 10; i++) {
			User user = Reg(BigInteger.valueOf(i));
			users.add(user);
		}

		return users;
	}

	/**
	 * Getter for param P
	 * @return p
	 */
	public BigInteger getP() {
		return this.p;
	}
	
	/**
	 * Getter for param Q
	 * @return q
	 */
	public BigInteger getQ() {
		return this.q;
	}
	
	/**
	 * Getter for rsaLambda
	 * @return security parameter for RSA Signature Scheme
	 */
	public int getSignatureSecurityParameter() {
		return rsaLambda;
	}
}
