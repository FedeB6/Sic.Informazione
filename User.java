package classes;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;

import javax.crypto.spec.IvParameterSpec;

import java.util.Scanner;

public class User {
	private static final String SERVER_ADDRESS = "localhost";
	private static final int PORT = 12346;

    public static void main(String[] args) {
        try {
        	//Lo user si connette alla socket esistente creata dal server
        	Socket socket = new Socket(SERVER_ADDRESS, PORT);
        	System.out.println("Connected to the server");
        	
        	//Stream di input e output per la comunicazione con il server
        	PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
        	
        	///////////DH Key Exchange///////////
            BigInteger prime, generator;
            //First Message
            System.out.println("Begin Key exchange...");
            prime = new BigInteger(in.readLine());
            generator = new BigInteger(in.readLine());
            System.out.println("Recieved prime number and corresponding generator");
            BigInteger Yserver = new BigInteger(in.readLine());
            System.out.println("Recieved server's 'Y' value");
            
            DHHandler dhh = new DHHandler(prime, generator);
            BigInteger Yclient = dhh.getPublicKey();
            out.println(Yclient);
            System.out.println("Sent 'Y' Value: " + Yclient);
            //Il client effettua le operazione complementari del server
            //Riceve come prima cosa numero primo e generatore con cui costruire il proprio DHHandler
            //Genera poi il proprio Yvalue e lo invia al server
            
            //Key generation
            System.out.println("Generating Key");
            Key dhKey = dhh.calculateKey(Yserver);
            System.out.println("Key was successfully generated");
            /////////////////////////////////////
            
            //Initialization Vector
            IvParameterSpec iv = new IvParameterSpec(in.readLine().getBytes()); //Si riceve l'IV scelto dal server
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
            Scanner scanner = new Scanner(System.in);
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
            socket.close();
            
        }catch(IOException e) {
        	e.printStackTrace();
        }
    }

}
