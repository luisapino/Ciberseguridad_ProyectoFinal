package server;

import crypto.CryptoUtils;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

import javafx.scene.control.TextArea;

public class Server {
    public static void runServer(TextArea logArea) throws Exception {
        File serverDir = new File("server_files");
        if (!serverDir.exists()) serverDir.mkdirs();

        ServerSocket serverSocket = new ServerSocket(5555);
        logArea.appendText("[Servidor] Esperando conexión...\n");

        Socket socket = serverSocket.accept();
        logArea.appendText("[Servidor] Cliente conectado.\n");

        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        CryptoUtils.saveKey("server_files/public_key_server.pem", publicKey);

        dos.writeInt(publicKey.getEncoded().length);
        dos.write(publicKey.getEncoded());
        dos.flush();

        int aesLen = dis.readInt();
        byte[] encryptedAES = dis.readNBytes(aesLen);
        byte[] aesKeyBytes = CryptoUtils.decryptRSA(encryptedAES, privateKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        int fileLen = dis.readInt();
        byte[] encryptedFile = dis.readNBytes(fileLen);
        byte[] decryptedFile = CryptoUtils.decryptAES(encryptedFile, aesKey);
        CryptoUtils.saveToFile("server_files/received_file.txt", decryptedFile);

        int hashLen = dis.readInt();
        byte[] clientHash = dis.readNBytes(hashLen);

        byte[] serverHash = CryptoUtils.sha256(decryptedFile);
        CryptoUtils.saveToFile("server_files/hash_servidor.hex", serverHash);

        if (MessageDigest.isEqual(clientHash, serverHash)) {
            logArea.appendText("[Servidor] Integridad verificada: OK.\n");
        } else {
            logArea.appendText("[Servidor] Integridad fallida.\n");
        }

        dis.close();
        dos.close();
        socket.close();
        serverSocket.close();
    }
}