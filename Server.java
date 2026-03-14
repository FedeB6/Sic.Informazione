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
    	
    	BigInteger prime = new BigInteger("67149524547258565451085655273701215867"); //Prime e generator rispettivamente Safe e Sophie Germain primes
    	BigInteger generator = new BigInteger("33574762273629282725542827636850607933"); //e sono scelti staticamente per il testing
    																				//Versioni effettive dello scambio richiedono che
    																				//i due numeri siano generati casualmente
    	
    	DHHandler dhh = new DHHandler(prime, generator);
    	Scanner scanner = new Scanner(System.in);
    	
        try {
        	///Setup del canale di comunicazione///
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server is running and waiting for connections...");

            Socket clientSocket = serverSocket.accept();
            System.out.println("New client connected: " + clientSocket);
            ///////////////////////////////////////
            
            ///////////DH Key Exchange///////////
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            
            //First Message
            System.out.println("Begin Key exchange...");System.out.println(System.lineSeparator());
            out.println(prime);
            System.out.println("Sent prime:" + prime);
            out.println(generator);
            System.out.println("Sent generator:" + generator);
            BigInteger Yserver = dhh.getPublicKey();
            out.println(Yserver);
            System.out.println("Sent 'Y' Value: " + Yserver);System.out.println(System.lineSeparator());
            //Il server invia il numero primo scelto il corrispondente generatore
            //Il server usa poi il suo DHHandler per calcolare Yserver = g^a dove g è il generatore e a è il nonce randomInt generato casualmente
            //e lo invia
            
            //Client response
            System.out.println("Waiting for client response...");System.out.println(System.lineSeparator());
            BigInteger Yclient = new BigInteger(in.readLine());
            System.out.println("Recieved client's 'Y' value");
            
            //Key generation
            System.out.println("Generating Key");
            Key dhKey = dhh.calculateKey(Yclient);
            System.out.println("Key was successfully generated");System.out.println(System.lineSeparator());
            /////////////////////////////////////
            		
            
            //Generazione dell'Initialization Vector
            String ivString = "1234567812345678";
            IvParameterSpec iv = new IvParameterSpec(ivString.getBytes()); //Si usa una stringa predefinita per generare il vettore di inizializzazione
            out.println(ivString);											//da utilizzare per la cifrare/decifrare i messaggi con CBC
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
