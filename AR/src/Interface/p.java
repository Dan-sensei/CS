/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Interface;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class p {
    public static String get_Hash (String password){
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
    
    public static String generateAESKey(){
        String AESkey = null;
        try{ 
            Key key;
            SecureRandom rand = new SecureRandom();
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256, rand);
            key = generator.generateKey();
            AESkey=Base64.getEncoder().encodeToString(key.getEncoded()).substring(0, 16);
        }catch(Exception e){
            e.printStackTrace();
        }
        return AESkey;
    }
    
    public static String aes(){
        String aes = null;
        try{ 
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();
            
            aes = Base64.getEncoder().encodeToString(secretKey.getEncoded()).substring(0, 16);
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return aes;
    }
    
    public static byte[] encryptAES(String key, String initVector, String mensaje) {

    	try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher encriptador = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            encriptador.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] cifrado = encriptador.doFinal(mensaje.getBytes());

            return cifrado;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
	// DESENCRIPTAR CON CLAVE AES
    public static String decryptAES(String key, String initVector, byte[] cifrado) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher encriptador = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            encriptador.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] mensaje = encriptador.doFinal(cifrado);

            return new String(mensaje);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
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

    // ENCRIPTAR CON RSA PUBLICA
    public static byte[] encryptRSA(String mensaje, PublicKey key){
        byte[] cifrado = null;
        try {
            Cipher encriptador = Cipher.getInstance("RSA");
            encriptador.init(Cipher.ENCRYPT_MODE, key);
            cifrado = encriptador.doFinal(mensaje.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cifrado;
    }

    // DESENCRIPTAR CON RSA PRIVADA
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
    public static void main(String args[]) {
        KeyPair keys = generateKeyPair();
        String p = "Dan";
       /*
        byte []s = p.getBytes();
        System.out.println(s);
        System.out.println(Base64.getEncoder().encodeToString(s));
        System.out.println("Hash -> "+get_Hash(p));
        */
        String aes = generateAESKey();

        byte []c = encryptAES(aes,"8u87y6t5r4efghyt",p);
        
        System.out.println( Base64.getEncoder().encodeToString(c));
        System.out.println( decryptAES(aes,"8u87y6t5r4efghyt",c));
    }
}
