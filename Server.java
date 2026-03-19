package classes;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import javax.crypto.spec.IvParameterSpec;
import java.util.Scanner;


public class Server {
    private static final int PORT = 12346;

    public static void main(String[] args) {
    	
    	/* Prime e generator rispettivamente Safe e Sophie Germain primes
    	 * e sono scelti staticamente per il testing
    	 * 
    	 * Versioni effettive dello scambio richiedono che
    	 * i due numeri siano scelti in modo casuale (ad esempio con TRNG)*/
    	
    	BigInteger prime = new BigInteger("67149524547258565451085655273701215867");
    	BigInteger generator = new BigInteger("33574762273629282725542827636850607933");
    	
    	
    	/* DHHandler è l'unità che si occupa di gestire le operazioni relative allo scambio DH
    	 * e alla cifratura e decifratura dei messaggi*/
    	
    	DHHandler dhh = new DHHandler(prime, generator);
    	Scanner scanner = new Scanner(System.in);
    	
        try {
        	/*Setup del canale di comunicazione*/
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server is running and waiting for connections...");

            Socket clientSocket = serverSocket.accept();
            System.out.println("New client connected: " + clientSocket);
            
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            /////////////////////////////////////
            
            ///////////DH Key Exchange///////////
            /* Lo scambio DH si articola in 4 passi:
             * 1) Il server invia al client prime e generator
             * 2) Il server invia al client Yserver = [generator^(secret)]mod(prime)
             * 3) Il server riceve dal client Yclient
             * 4) Il server calcola la dhKey condivisa con il client*/
            
            //1)
            System.out.println("Begin Key exchange...");System.out.println(System.lineSeparator());
            out.println(prime);
            System.out.println("Sent prime:" + prime);
            out.println(generator);
            System.out.println("Sent generator:" + generator);
            //2)
            BigInteger Yserver = dhh.getPublicKey();
            out.println(Yserver);
            System.out.println("Sent 'Y' Value: " + Yserver);System.out.println(System.lineSeparator());
            //3)
            System.out.println("Waiting for client response...");System.out.println(System.lineSeparator());
            BigInteger Yclient = new BigInteger(in.readLine());
            System.out.println("Recieved client's 'Y' value");
            
            //4)
            System.out.println("Generating Key");
            Key dhKey = dhh.calculateKey(Yclient);
            System.out.println("Key was successfully generated");System.out.println(System.lineSeparator());
            /////////////////////////////////////
            		
            
            /* Generazione dell'Initialization Vector
             * Anche in questo caso l'IV è scelto staticamente per il testing
             * Un implementazione reale di cifratura con CBC richiede che l'IV sia scelto in modo casuale ed sia monouso*/
            String ivString = "1234567812345678";
            IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());
            out.println(ivString);
            System.out.println("Sent IV");System.out.println(System.lineSeparator());
            
            //Regular communication
            System.out.println(System.lineSeparator());System.out.println("Begin communication");System.out.println(System.lineSeparator());
            System.out.println("Input 'Bye' to end  the communication");System.out.println(System.lineSeparator());
            
            //Thread per la gestione dei messaggi in arrivo
            new Thread(() -> {
                try {
                    String cipherClient;
                    while ((cipherClient = in.readLine()) != null) {
                    	String decypheredText = dhh.decrypt(cipherClient, dhKey, iv);
                        System.out.println(decypheredText);
                        if(decypheredText.compareTo("Bye") == 0) {
                        	System.out.println("Client ended communications...");System.out.println(System.lineSeparator());
                    		break;
                        }
                    }
                    return;
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
            
            
            //Gestione dei messaggi da inviare
            String plain, cipherText;
            while(true) {
            	plain = scanner.nextLine();
            	
            	cipherText = dhh.encrypt(plain, dhKey, iv);
            	out.println(cipherText);
            	//Chiusura della comunicazione dopo che Bye è stato inviato
            	if(plain.compareTo("Bye") == 0) {
            		System.out.println("Ending communication...");System.out.println(System.lineSeparator());
            		break;
            	}
            }
            
            //Cleanup
            scanner.close();
            out.close();
            in.close();
            clientSocket.close();
            serverSocket.close();
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }   
    
}
