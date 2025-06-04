package crypto;

import javax.crypto.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;

/**
 * Utilidades criptográficas que proporcionan funciones para generar claves,
 * cifrar, descifrar y calcular hashes utilizando RSA, AES y SHA-256.
 */
public class CryptoUtils {

    /**
     * Genera un par de claves RSA de 2048 bits.
     *
     * @return Un objeto {@link KeyPair} que contiene la clave pública y privada.
     * @throws Exception Si ocurre un error durante la generación de claves.
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Genera una clave secreta AES de 256 bits.
     *
     * @return Una clave secreta {@link SecretKey} para cifrado AES.
     * @throws Exception Si ocurre un error durante la generación de la clave.
     */
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    /**
     * Cifra datos usando el algoritmo RSA y una clave pública.
     *
     * @param data Los datos a cifrar.
     * @param key  La clave pública para el cifrado.
     * @return Los datos cifrados en formato de arreglo de bytes.
     * @throws Exception Si ocurre un error durante el cifrado.
     */
    public static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Descifra datos cifrados con RSA utilizando una clave privada.
     *
     * @param data Los datos cifrados.
     * @param key  La clave privada para descifrar.
     * @return Los datos originales descifrados.
     * @throws Exception Si ocurre un error durante el descifrado.
     */
    public static byte[] decryptRSA(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Cifra datos usando el algoritmo AES y una clave secreta.
     *
     * @param data Los datos a cifrar.
     * @param key  La clave secreta AES.
     * @return Los datos cifrados en formato de arreglo de bytes.
     * @throws Exception Si ocurre un error durante el cifrado.
     */
    public static byte[] encryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Descifra datos cifrados con AES utilizando una clave secreta.
     *
     * @param data Los datos cifrados.
     * @param key  La clave secreta AES.
     * @return Los datos originales descifrados.
     * @throws Exception Si ocurre un error durante el descifrado.
     */
    public static byte[] decryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Calcula el hash SHA-256 de un arreglo de bytes.
     *
     * @param data Los datos de entrada.
     * @return El hash SHA-256 en formato de arreglo de bytes.
     * @throws Exception Si ocurre un error durante el cálculo del hash.
     */
    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    /**
     * Guarda un arreglo de bytes en un archivo en el sistema de archivos.
     *
     * @param path Ruta donde se guardará el archivo.
     * @param data Datos a guardar.
     * @throws IOException Si ocurre un error durante la escritura del archivo.
     */
    public static void saveToFile(String path, byte[] data) throws IOException {
        Files.write(Paths.get(path), data);
    }

    /**
     * Guarda una clave (pública, privada o secreta) en un archivo.
     *
     * @param path Ruta donde se guardará la clave.
     * @param key  Clave a guardar.
     * @throws IOException Si ocurre un error durante la escritura del archivo.
     */
    public static void saveKey(String path, Key key) throws IOException {
        Files.write(Paths.get(path), key.getEncoded());
    }
}