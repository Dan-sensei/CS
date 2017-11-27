package Interface;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;

import java.net.InetAddress;
import java.net.UnknownHostException;


/**
 * A multithreaded chat room server.  When a client connects the
 * server requests a screen name by sending the client the
 * text "SUBMITNAME", and keeps requesting a name until
 * a unique one is received.  After a client submits a unique
 * name, the server acknowledges with "NAMEACCEPTED".  Then
 * all messages from that client will be broadcast to all other
 * clients that have submitted a unique screen name.  The
 * broadcast messages are prefixed with "MESSAGE ".
 *
 * Because this is just a teaching example to illustrate a simple
 * chat server, there are a few features that have been left out.
 * Two are very useful and belong in production code:
 *
 *     1. The protocol should be enhanced so that the client can
 *        send clean disconnect messages to the server.
 *
 *     2. The server should do some logging.
 */

public class Server {

    /**
     * The port that the server listens on.
     */
    private static final int PORT = 9001;


    private static HashMap<String,PrintWriter> user;
    private static HashMap<String,String> public_rsa;
    /**
     * The appplication main method, which just listens on a port and
     * spawns handler threads.
     */
    public static void main(String[] args) throws Exception {
        System.out.println("The chat server is running.");
        
        user = new HashMap<String,PrintWriter>();
        public_rsa = new HashMap<String, String>();
        InetAddress ip;
        try {
            ip = InetAddress.getLocalHost();
            System.out.println("Current IP address : " + ip.getHostAddress());
        } catch (UnknownHostException e) {
            e.printStackTrace();
            System.exit(0);
        }

        ServerSocket listener = new ServerSocket(PORT);
        try {
            while (true) {
                new Handler(listener.accept()).start();
            }
        } finally {
            listener.close();
        }
    }

    /**
     * A handler thread class.  Handlers are spawned from the listening
     * loop and are responsible for a dealing with a single client
     * and broadcasting its messages.
     */
    
    private static class Handler extends Thread {
        private String name;
        private Socket socket;
        private BufferedReader in;
        private PrintWriter out;

        /**
         * Constructs a handler thread, squirreling away the socket.
         * All the interesting work is done in the run method.
         */
        public Handler(Socket s) {
            socket = s;
        }

        /**
         * Services this thread's client by repeatedly requesting a
         * screen name until a unique one has been submitted, then
         * acknowledges the name and registers the output stream for
         * the client in a global set, then repeatedly gets inputs and
         * broadcasts them.
         */
        public void run() {
            try {

                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                while (true) {
                    out.println("SUBMITNAME");
                    name = in.readLine();
                    System.out.println(name);
                    if (name.equals("") )
                        return;       
                    synchronized (user) {
                        if (!user.containsKey(name)) {
                            user.put(name, out);
                            user.forEach(
                                (k,v)->refresh(k)
                            );
                            break;
                        }
                    }
                }

                out.println("NAMEACCEPTED");
                String dest;
                String input;
                String m;
                while (true) {
                    m=in.readLine();
                    dest = in.readLine();
                    System.out.println("Message received: "+m);
                    System.out.println("Dest: "+dest);
                    switch (m){
                        case "MESSAGE":         input=in.readLine();
                                                System.out.println("Input: "+input);
                                                /*
                                                user.get("HACKER").println("MESSAGE");
                                                user.get("HACKER").println(name + ": ");
                                                user.get("HACKER").println(input);
                                                */
                                                user.get(dest).println("MESSAGE");
                                                user.get(dest).println(name + ":");
                                                user.get(dest).println(input);
                                                break;
                                            
                        case "RSA_Request":     System.out.println("RSA_Request"+public_rsa.get(dest));
                                                out.println("RSA_Request");
                                                out.println(public_rsa.get(dest));
                                                break;
                                            
                        case "RSA_Push":        String rsa = in.readLine();
                                                System.out.println("RSA Push to "+dest+" "+rsa);
                                                user.get(dest).println("RSA");
                                                user.get(dest).println(name);
                                                user.get(dest).println(rsa);
                                                break;     
                                            
                        case "RSA_Register":    public_rsa.put(name, dest);
                                                break;
                    }
                }
            } catch (IOException e) {
                System.out.println(e);
            } finally {
                if (user != null) {
                    user.remove(name);
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }
        
        private void refresh(String k){
            if(k!=name){
                user.get(name).println("ADD");
                user.get(name).println(k);
                user.get(k).println("ADD");
                user.get(k).println(name);
            }
        }
    }
}

                    /*
                    if(m.equals("MESSAGE")){
                        dest = in.readLine();
                        input=in.readLine();
                        System.out.println(dest + " "+input);
                        if (dest==null || input == null) {
                            return;
                        }
                        System.out.println("Received "+input);  
                        user.get("HACKER").println("MESSAGE " + name + ": ");
                        user.get("HACKER").println(input);
                        user.get(dest).println("MESSAGE " + name + ": ");
                        user.get(dest).println(input);
                    }
                    else if (m.equals("RSA_request")){
                        dest = in.readLine();
                        //System.out.println("getRSA() SERVER "+dest+" "+public_rsa.get(dest));
                        out.println("RSA_request"+public_rsa.get(dest));
                    }
                    else if(m.equals("RSA_push")){
                        dest = in.readLine();
                        String rsa = in.readLine();
                        //System.out.println("RSA Push to "+dest+" "+rsa);
                        user.get(dest).println("RSA "+name);
                        user.get(dest).println(rsa);
                    }
                    else if (m.equals("RSA_Register")){
                        public_rsa.put(name, in.readLine());
                        //System.out.println("Server "+name+" "+public_rsa.get(name));
                    }
                    */