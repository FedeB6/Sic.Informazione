package classes;

import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DHHandler {
	
	protected BigInteger prime;
	protected BigInteger generator;
	protected BigInteger secret;
	
	public DHHandler(BigInteger p, BigInteger g) {	//Il costruttore si limita a chiamare il metodo di inizializzazione
		init(p, g);
	}
	
	private void init(BigInteger p, BigInteger g) { //Metodo di inizializzazione dell'handler
		this.prime = p;
		this.generator = g;
		
		SecureRandom random = new SecureRandom();
		this.secret = new BigInteger(p.bitLength()-1, 5, random);
		/*Il metodo salva il n. primo e il generatore associato passatogli e in seguito genera il numero casuale che verrà utilizzato durante lo scambio*/
	}
	
	public BigInteger getPublicKey() {	//Ritorna un BigInteger risultato dell'operazione generator^(secret)mod(prime)
		return generator.modPow(secret, prime);
	}
	
	public Key calculateKey(BigInteger recievedKey) {	//Ritorna la chiave finale condivisa da entrambi gli utenti calcolando
		BigInteger bigIntKey = recievedKey.modPow(secret, prime);	//recievedKey^(secret)mod(prime)
		SecretKeySpec key = new SecretKeySpec(bigIntKey.toByteArray(), "AES");
		return(key);
	}
	
	
	public String encrypt(String input, Key key, AlgorithmParameterSpec iv){
		byte[] cipherText = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //Avendo scelto di usare CBC è richiesto anche di utilizzare un IV
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			cipherText = cipher.doFinal(input.getBytes());
		}catch(Exception e) {
			e.printStackTrace();
		}
		return Base64.getEncoder().encodeToString(cipherText);
	}
	public String decrypt(String input, Key key, AlgorithmParameterSpec iv) {
		byte[] plainText = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //Avendo scelto di usare CBC è richiesto anche di utilizzare un IV
			cipher.init(Cipher.DECRYPT_MODE, key, iv);	
			plainText = cipher.doFinal(Base64.getDecoder().decode(input));
		}catch(Exception e) {
			e.printStackTrace();
		}
		return(new String(plainText));
	}
}
