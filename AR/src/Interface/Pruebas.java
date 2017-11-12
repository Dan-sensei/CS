package Interface;

import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Pruebas {

	// ENCRIPTAR CON CLAVE AES
	public static String encryptAES(String key, String initVector, String mensaje) {

    	try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher encriptador = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            encriptador.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] cifrado = encriptador.doFinal(mensaje.getBytes());

            return Base64.getEncoder().encodeToString(cifrado);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
	// DESENCRIPTAR CON CLAVE AES
    public static String decryptAES(String key, String initVector, String cifrado) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher encriptador = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            encriptador.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] mensaje = encriptador.doFinal(Base64.getDecoder().decode(cifrado));

            return new String(mensaje);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    // GENERAR PAR DE CLAVES (PUBLICA Y PRIVADA)
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
    
	public static void main(String[] args) {
		
	 	String mensaje="SHAHAB";
        String key = "Bar12345Bar12345"; // 128 bit key
        String initVector = "8u87y6t5r4efghyt"; // 16 bytes IV

        System.out.println("Mensaje cifrado: " + encryptAES(key, initVector, mensaje));
        System.out.println("----------");
        System.out.println("Mensaje descifrado: " + decryptAES(key, initVector,encryptAES(key, initVector, mensaje)));
        System.out.println("----------");
        KeyPair keyPair;
        
        // Crea dos claves (publica y privada)
        keyPair  = generateKeyPair();
        
        // Utilizamos la clave publica de RSA para cifrar la clave AES 
        byte [] cifrado = encryptRSA(key,keyPair.getPublic());
        System.out.println("Clave AES cifrada con RSA publica: " + Base64.getEncoder().encodeToString(cifrado));
        System.out.println("----------");
        
        // Utilizar la clave privada de RSA para descifrar la clave AES 
        String texto = decryptRSA(cifrado, keyPair.getPrivate());
        System.out.println("Clave AES descifrada con RSA privada: " + texto);
        
	}
}
