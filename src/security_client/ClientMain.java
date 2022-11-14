package security_client;

public class ClientMain {
  public static void main(String[] args) throws Exception {
    int no = 1;
    int times = 1;
    if(args != null && args.length > 0) {
      no = Integer.parseInt(args[0]);
      if(args.length > 1) {
        times = Integer.parseInt(args[1]);
      }
    }
    for(int j = 0; j < times; j++) {
      //System.out.println("round "+(j+1));
      ClientThread[] threads = new ClientThread[no];
      for(int i = 0; i < no; i++) {
        threads[i] = new ClientThread();
      }
      for(int i = 0; i < no; i++) {
        threads[i].start();
      }
      for(int i = 0; i < no; i++) {
        threads[i].join();
      }
      //System.out.println("round "+(j+1)+"done");
    }
  }
}
