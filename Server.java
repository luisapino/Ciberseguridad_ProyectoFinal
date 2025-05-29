import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;

public class Server {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5555);
        System.out.println("[Servidor] Esperando conexión en puerto 5555...");

        new File("server_files").mkdir();

        Socket socket = serverSocket.accept();
        System.out.println("[Servidor] Cliente conectado.");

        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        CryptoUtils.saveKey("server_files/public_key_server.pem", publicKey);

        dos.writeInt(publicKey.getEncoded().length);
        dos.write(publicKey.getEncoded());
        dos.flush();
        System.out.println("[Servidor] Clave pública enviada.");

        int aesLen = dis.readInt();
        byte[] encryptedAES = dis.readNBytes(aesLen);
        byte[] aesKeyBytes = CryptoUtils.decryptRSA(encryptedAES, privateKey);
        CryptoUtils.saveToFile("server_files/aes_key_descifrada.hex", aesKeyBytes);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        System.out.println("[Servidor] Clave AES recibida y descifrada.");

        int fileLen = dis.readInt();
        byte[] encryptedFile = dis.readNBytes(fileLen);
        byte[] decryptedFile = CryptoUtils.decryptAES(encryptedFile, aesKey);
        CryptoUtils.saveToFile("server_files/received_file.txt", decryptedFile);

        int hashLen = dis.readInt();
        byte[] clientHash = dis.readNBytes(hashLen);
        CryptoUtils.saveToFile("server_files/hash_servidor.hex", CryptoUtils.sha256(decryptedFile));

        byte[] serverHash = CryptoUtils.sha256(decryptedFile);

        if (MessageDigest.isEqual(clientHash, serverHash)) {
            System.out.println("[Servidor] Archivo recibido correctamente con integridad verificada.");
        } else {
            System.out.println("[Servidor] Error: El archivo fue alterado o corrompido.");
        }

        dis.close();
        dos.close();
        socket.close();
        serverSocket.close();
    }
}
