import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

public class ElGamal {

	public static Key pubKey;
	
	/**
	 * Generates the pair of private and public key for ElGamal
	 * @param Prime p
	 * @param Generator g
	 * @param random
	 * @return KeyPair
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public KeyPair generateKeyPair(BigInteger p, BigInteger g, SecureRandom random) 
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		ElGamalParameterSpec specParams = new ElGamalParameterSpec(p,g);
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC");
		generator.initialize(specParams, random);
		KeyPair pair = generator.generateKeyPair();
		pubKey = pair.getPublic();
		return pair;
	}

	/**
	 * Encrypts the plain text into a cipher text suing ElGamal encryption scheme
	 * 
	 * @param plainText
	 * @param publicKey
	 * @return encrypted cipherText
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 */
	public byte[] encrypt(byte[] plainText, Key pubKey) throws IOException, InvalidCipherTextException {
		AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(pubKey.getEncoded());

		AsymmetricBlockCipher cipher = new ElGamalEngine();
		cipher.init(true, publicKey);
		byte[] cipherText = cipher.processBlock(plainText, 0, plainText.length);

		return cipherText;
	}

	/**
	 * Decrypts a ElGamal cipher text into a plain text
	 * 
	 * @param cipherText
	 * @param private key 
	 * @return plainText 
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 */
	public byte[] decrypt(byte[] cipherText, Key privKey) throws IOException, InvalidCipherTextException {
		AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(privKey.getEncoded());
		AsymmetricBlockCipher cipher = new ElGamalEngine();
		cipher.init(false, privateKey);

		byte[] plainText = cipher.processBlock(cipherText, 0, cipherText.length);

		return plainText;
	}

	/**
	 * Evaluates two encrypted messages with the multiplicative homomorphic Enc(m1) * Enc(m2) = Enc(m1*m2) returns decrypted value
	 * @param m1_e
	 * @param m2_e
	 * @param dk
	 * @return Dec(m1*m2) 
	 * @throws InvalidCipherTextException
	 * @throws IOException
	 */
	public byte[] evaluate(byte[] m1_e, byte[] m2_e, Key dk) throws InvalidCipherTextException, IOException {
		ElGamalPublicKey pub = (ElGamalPublicKey) pubKey;
		BigInteger p = pub.getParameters().getP();

		byte[] combined = new byte[m1_e.length];

		byte[] a = new byte[combined.length / 2];
		byte[] b = new byte[combined.length / 2];

		System.arraycopy(m1_e, 0, a, 0, a.length);
		System.arraycopy(m1_e, a.length, b, 0, b.length);

		BigInteger a1 = new BigInteger(1, a);
		BigInteger b1 = new BigInteger(1, b);

		System.arraycopy(m2_e, 0, a, 0, a.length);
		System.arraycopy(m2_e, a.length, b, 0, b.length);

		BigInteger a2 = new BigInteger(1, a);
		BigInteger b2 = new BigInteger(1, b);

		BigInteger numA = (a1.multiply(a2)).mod(p);
		BigInteger numB = (b1.multiply(b2)).mod(p);

		a = numA.toByteArray();
		b = numB.toByteArray();

		if (a.length > combined.length / 2) {
			System.arraycopy(a, 1, combined, combined.length / 2 - (a.length - 1), a.length - 1);
		} else {
			System.arraycopy(a, 0, combined, combined.length / 2 - a.length, a.length);
		}

		if (b.length > combined.length / 2) {
			System.arraycopy(b, 1, combined, combined.length - (b.length - 1), b.length - 1);
		} else {
			System.arraycopy(b, 0, combined, combined.length - b.length, b.length);
		}

		return decrypt(combined, dk);
	}

	/**
	 * Multiplies two cipher texts into one, returns encrypted value
	 * @param m1_e
	 * @param m2_e
	 * @param encryption key
	 * @return Enc(m1 * m2)
	 */
	public byte[] multiply(byte[] m1_e, byte[] m2_e, Key ek) {
		ElGamalPublicKey pub = (ElGamalPublicKey) ek;
		BigInteger p = pub.getParameters().getP();

		byte[] combined = new byte[m1_e.length];

		byte[] a = new byte[combined.length / 2];
		byte[] b = new byte[combined.length / 2];
		
		System.arraycopy(m1_e, 0, a, 0, a.length);
		System.arraycopy(m1_e, a.length, b, 0, b.length);

		BigInteger a1 = new BigInteger(1, a);
		BigInteger b1 = new BigInteger(1, b);

		System.arraycopy(m2_e, 0, a, 0, a.length);
		System.arraycopy(m2_e, a.length, b, 0, b.length);

		BigInteger a2 = new BigInteger(1, a);
		BigInteger b2 = new BigInteger(1, b);

		BigInteger numA = (a1.multiply(a2)).mod(p);
		BigInteger numB = (b1.multiply(b2)).mod(p);

		a = numA.toByteArray();
		b = numB.toByteArray();

		if (a.length > combined.length / 2) {
			System.arraycopy(a, 1, combined, combined.length / 2 - (a.length - 1), a.length - 1);
		} else {
			System.arraycopy(a, 0, combined, combined.length / 2 - a.length, a.length);
		}

		if (b.length > combined.length / 2) {
			System.arraycopy(b, 1, combined, combined.length - (b.length - 1), b.length - 1);
		} else {
			System.arraycopy(b, 0, combined, combined.length - b.length, b.length);
		}

		return combined;
	}

	/**
	 * Enc(m1)^B
	 * @param m1_e
	 * @param B - exponent
	 * @param encryption_key
	 * @return Enc(m1^B)
	 */
	public byte[] pow(byte[] m1_e, BigInteger B, Key ek) {
		ElGamalPublicKey pub = (ElGamalPublicKey) ek;
		BigInteger p = pub.getParameters().getP();

		byte[] m1_ec = new byte[m1_e.length];
		byte[] a = new byte[m1_e.length / 2];
		byte[] b = new byte[m1_e.length / 2];

		System.arraycopy(m1_e, 0, a, 0, a.length);
		System.arraycopy(m1_e, a.length, b, 0, b.length);

		BigInteger numA = new BigInteger(1, a);
		BigInteger numB = new BigInteger(1, b);

		numA = numA.modPow(B, p);
		numB = numB.modPow(B, p);

		a = numA.toByteArray();
		b = numB.toByteArray();

		if (a.length > m1_ec.length / 2) {
			System.arraycopy(a, 1, m1_ec, m1_ec.length / 2 - (a.length - 1), a.length - 1);
		} else {
			System.arraycopy(a, 0, m1_ec, m1_ec.length / 2 - a.length, a.length);
		}

		if (b.length > m1_ec.length / 2) {
			System.arraycopy(b, 1, m1_ec, m1_ec.length - (b.length - 1), b.length - 1);
		} else {
			System.arraycopy(b, 0, m1_ec, m1_ec.length - b.length, b.length);
		}

		return m1_ec;
	}
}

