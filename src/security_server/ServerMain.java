package seguridad20222_servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class ServidorMain {
	
	private static ServerSocket ss;	
	private static final String ID = "Main Server: ";
	private static int puerto = 4030;

	public static void main(String[] args) throws IOException {
		
		System.out.println(ID + "Starting main server. Port: " + puerto);
		
		int idThread = 0;
		ss = new ServerSocket(puerto);
		System.out.println(ID + "Creating socket: done");
		String options = "210";
		
		while (true) {
		    Random optRandom = new Random();
			int opt = optRandom.nextInt()%6;
			if (idThread%3==0) {
				switch (opt) {
				case 0:
					options = "012";
					break;
				case 1:
					options = "021";
					break;
				case 2: 
					options = "102";
					break;
				case 3:
					options = "120";
					break;
				case 4:
					options = "201";
					break;
				default:
					options = "210";
					break;
				}
			}

			try { 
				// Crea un delegado por cliente. Atiende por conexion. 
				//semaforo.acquire();
				Socket sc = ss.accept();
				System.out.println(ID + " delegate " + idThread + ": accepting client - done");
				int pos = idThread % 3;
				int mod = options.charAt(pos) - '0';
				SrvThread d = new SrvThread(sc,idThread,mod);
				idThread++;
				d.start();
			} catch (IOException e) {
				System.out.println(ID + " delegate " + idThread + ": accepting client - ERROR");
				e.printStackTrace();
			}
		}

	}

}
