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
	
	public DHHandler(BigInteger p, BigInteger g) {
		//Il costruttore chiama il metodo di inizializzazione
		init(p, g);
	}
	
	private void init(BigInteger p, BigInteger g) {
		/* L'inizializzazione dell'handler richiede
		 * per prima cosa di salvare i due BigInteger passati nei campi prime e generator in modo che possano poi essere usati
		 * per effettuare lo scambio DH e generare la chiave condivisa
		 * 
		 * Dopo il salvataggio di p e g il metodo genera casualmente un terzo BigInteger che funzionerà da valore segreto (ognuna delle
		 * parti comunicanti genererà il proprio segreto) con cui sono calcolati prima i valori da scambiare ed in seguito la chiave condivisa
		 * */
		this.prime = p;
		this.generator = g;
		
		SecureRandom random = new SecureRandom();
		this.secret = new BigInteger(p.bitLength()-1, 5, random);
	}
	
	public BigInteger getPublicKey() {
		/* getPublicKey() rappresenta il primo step di calcolo dello scambio DH
		 * entrambe le parti comunicanti chiamando il metodo eseguiranno l'operazione [generator^(secret)]mod(prime) ottenendo rispettivamente i valori
		 * "Va" e "Vb" che sono i parametri che dovranno scambiarsi per poter calcolare la chiave condivisa
		 * */
		return generator.modPow(secret, prime);
	}
	
	public Key calculateKey(BigInteger recievedKey) {
		/* calculateKey() è il passo finale dello scambio DH che calcola la chiave condivisa dalle parti comunicanti
		 * come prima cosa calcola bigIntKey che è il risultato dell'operazione [recievedKey^(secret)]mod(prime) (dove recievedKey è il risultato
		 * dell'operazione getPublicKey() ricevuto dall'interlocutore)
		 * 
		 * calcolata la chiave in forma BigInteger viene incapsulata in un SecretKeySpec in modo da poter essere utilizzata con la classe Cipher
		 * per cifrare i messaggi inviati durante la comunicazione+
		 * */
		BigInteger bigIntKey = recievedKey.modPow(secret, prime);
		SecretKeySpec key = new SecretKeySpec(bigIntKey.toByteArray(), "AES");
		return(key);
	}
	
	
	public String encrypt(String input, Key key, AlgorithmParameterSpec iv){
		/* encrypt() cifra il messaggio passato tramite chiave restituendo la stringa cifrata risultante
		 * scegliendo Cypher Block Chaining come metodo di cifratura è necessario passare alla funzione anche un vettore di inizializzazione
		 * in modo che cifratura e decifratura possano essere eseguite in modo sicuro
		 * 
		 * metodo complementare di decrypt()*/
		byte[] cipherText = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			cipherText = cipher.doFinal(input.getBytes());
		}catch(Exception e) {
			e.printStackTrace();
		}
		return Base64.getEncoder().encodeToString(cipherText);
	}
	public String decrypt(String input, Key key, AlgorithmParameterSpec iv) {
		/* decrypt() decifra il messaggio passato tramite chiave restituendo la stringa in chiaro risultante
		 * scegliendo Cypher Block Chaining come metodo di cifratura è necessario passare alla funzione anche un vettore di inizializzazione
		 * in modo che cifratura e decifratura possano essere eseguite in modo sicuro
		 * 
		 * metodo complementare di encrypt()*/
		byte[] plainText = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, iv);	
			plainText = cipher.doFinal(Base64.getDecoder().decode(input));
		}catch(Exception e) {
			e.printStackTrace();
		}
		return(new String(plainText));
	}
}
