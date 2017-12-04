package Interface;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

public class Server {

    private static final int PORT = 9001;

    private static HashMap<String,PrintWriter> user;
    private static HashMap<String,String> public_rsa;
    
    public static void main(String[] args) throws Exception {
        System.out.println("El servidor está en marcha");
        
        user = new HashMap<String,PrintWriter>();
        public_rsa = new HashMap<String, String>();
        InetAddress ip;
        try {
            ip = InetAddress.getLocalHost();
            System.out.println("IP Actual : " + ip.getHostAddress());
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

    
    private static class Handler extends Thread {
        private String name;
        private String pass;
        private Socket socket;
        private BufferedReader in;
        private PrintWriter out;
        
        private BufferedReader reader;
        private BufferedWriter writer;
        String hash;
        KeyPair keys;

        public Handler(Socket s) {
            socket = s;
            hash = "Hash.txt";
            keys = generateKeyPair();
            base_check(hash);
            try{
                reader = new BufferedReader(new FileReader(hash));
                writer = new BufferedWriter(new FileWriter(hash, true));
            }catch(Exception e){}
        }
        public void run() {
            try {

                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);
                String status;
                
                out.println(Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
                while (true) {
                    out.println("SUBMITNAME");
  
                    name = decryptRSA(Base64.getDecoder().decode(in.readLine().getBytes()),keys.getPrivate());
                    pass = decryptRSA(Base64.getDecoder().decode(in.readLine().getBytes()),keys.getPrivate());
                    
                    System.out.println(name);
                    System.out.println(pass);
                    status = loging(name, pass);
                    
                    if(status.equals("REGISTERED") || status.equals("LOGED")){
                        if (!user.containsKey(name)) {
                            user.put(name, out);
                            user.forEach(
                                (k,v)->refresh(k)
                            );
                        }
                        break;
                    }

                    /*
                    synchronized (user) {
                        if (!user.containsKey(name)) {
                            user.put(name, out);
                            user.forEach(
                                (k,v)->refresh(k)
                            );
                            break;
                        }
                    }
                    */
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
                                                /*
                                                user.get("HACKER").println("MESSAGE");
                                                user.get("HACKER").println(name + ": ");
                                                user.get("HACKER").println(input);
                                                */
                                                user.get(dest).println("MESSAGE");
                                                user.get(dest).println(name);
                                                user.get(dest).println(input);
                                                break;
                                            
                        case "RSA_Request":     System.out.println("RSA_Request"+public_rsa.get(dest));
                                                out.println("RSA_Request");
                                                out.println(public_rsa.get(dest));
                                                break;
                                            
                        case "RSA_Push":        String rsa = in.readLine();
                                                System.out.println("RSA Push to "+dest+" "+rsa);
                                                user.get(dest).println("RSA_Insert");
                                                user.get(dest).println(name);
                                                user.get(dest).println(rsa);
                                                break;     
                                            
                        case "RSA_Register":    public_rsa.put(name, dest);
                                                break;
                    }
                }
            } catch (IOException e) { System.out.println(e);} 
            
            finally {
                if (user != null) 
                    user.remove(name);   
                try {
                    socket.close();
                } catch (IOException e) {}
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
        
        
        public static String decryptRSA(byte[] cifrado, PrivateKey key){
            byte[] mensaje = null;
            try {
                Cipher encriptador = Cipher.getInstance("RSA");
                encriptador.init(Cipher.DECRYPT_MODE, key);
                mensaje = encriptador.doFinal(cifrado);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return new String(mensaje);
        }
        
        public static KeyPair generateKeyPair(){
            KeyPair keyPair = null;
            try {

                KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
                rsaKeyGen.initialize(1024);
                keyPair = rsaKeyGen.generateKeyPair();
                //PublicKey publicKey = keyPair.getPublic();

            } catch (Exception e) {
                e.printStackTrace();
            }
            return keyPair;
        }
        
        public static String encodeHash (String password){
            String hashed = null;
            try{
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(password.getBytes());
                hashed= Base64.getEncoder().encodeToString(hash);
            }

            catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }
            return hashed;
        }
        
        //-------------------METODOS PARA LOGIN----------------------
        void base_check(String filename) {
            File data_base = new File(filename);
            if (!data_base.exists()) {
                try {
                    System.out.println("Creating file");
                    data_base.createNewFile();
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        
        public String loging(String username, String password) {
            try {
                reader = new BufferedReader(new FileReader(hash));
                writer = new BufferedWriter(new FileWriter(hash, true));
                
                String sn, sp;
                sn = reader.readLine();
                while(sn!=null){
                    sp = reader.readLine();
                    if (sn.equals(encodeHash(username))) {
                        if(sp.equals(password)) return "LOGED";
                        else return "ERROR";
                    }
                    sn = reader.readLine();
                }
                System.out.println("Writing: "+username + " "+password);
                writer.write(encodeHash(username));
                writer.newLine();
                writer.write(password);
                writer.newLine();
                writer.close();
            } catch (IOException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            }
            return "REGISTERED";
        }
    }
}