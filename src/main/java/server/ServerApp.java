package server;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

public class ServerApp extends Application {
    private TextArea logArea;
    private Label statusLabel;
    private Label connectionInfoLabel;
    private Label securityInfoLabel;
    private Button startButton;
    private Button stopButton;
    private ProgressBar operationProgress;
    private boolean serverRunning = false;

    @Override
    public void start(Stage stage) {
        stage.setTitle("🛡️ Servidor - Transferencia Segura de Archivos");

        Label titleLabel = new Label("Servidor de Transferencia Segura");
        titleLabel.setFont(Font.font("Arial", FontWeight.BOLD, 18));
        titleLabel.setTextFill(Color.DARKGREEN);

        VBox controlSection = createControlSection();

        VBox statusSection = createStatusSection();

        VBox securitySection = createSecuritySection();

        VBox logSection = createLogSection();

        VBox root = new VBox(15);
        root.setPadding(new Insets(20));
        root.setStyle("-fx-background-color: #f0f8f0;");

        root.getChildren().addAll(
                titleLabel,
                createSeparator(),
                controlSection,
                createSeparator(),
                statusSection,
                createSeparator(),
                securitySection,
                createSeparator(),
                logSection
        );

        Scene scene = new Scene(new ScrollPane(root), 750, 700);
        stage.setScene(scene);
        stage.show();

        logArea.appendText("=== SERVIDOR DE TRANSFERENCIA SEGURA ===\n");
        logArea.appendText("🔐 Protocolo: RSA-2048 + AES-256 + SHA-256\n");
        logArea.appendText("📡 Puerto: 5555\n");
        logArea.appendText("🛡️ Verificación de integridad: SHA-256\n");
        logArea.appendText("Estado: Listo para iniciar...\n\n");
    }

    private VBox createControlSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("⚙️ Control del Servidor");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        startButton = new Button("🚀 Iniciar Servidor");
        startButton.setStyle("-fx-background-color: #4CAF50; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        startButton.setPrefWidth(200);
        startButton.setOnAction(e -> startServer());

        stopButton = new Button("⏹️ Detener Servidor");
        stopButton.setStyle("-fx-background-color: #f44336; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        stopButton.setPrefWidth(200);
        stopButton.setDisable(true);
        stopButton.setOnAction(e -> stopServer());

        HBox buttonBox = new HBox(15, startButton, stopButton);

        section.getChildren().addAll(sectionTitle, buttonBox);
        return section;
    }

    private VBox createStatusSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📊 Estado del Servidor");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        statusLabel = new Label("🔴 Servidor detenido");
        statusLabel.setFont(Font.font("Arial", FontWeight.BOLD, 12));
        statusLabel.setTextFill(Color.RED);

        connectionInfoLabel = new Label("Esperando conexiones...");
        connectionInfoLabel.setTextFill(Color.GRAY);

        operationProgress = new ProgressBar(0);
        operationProgress.setPrefWidth(400);
        operationProgress.setStyle("-fx-accent: #4CAF50;");
        operationProgress.setVisible(false);

        section.getChildren().addAll(sectionTitle, statusLabel, connectionInfoLabel, operationProgress);
        return section;
    }

    private VBox createSecuritySection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("🔒 Información de Seguridad");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        securityInfoLabel = new Label("🔐 RSA-2048: Intercambio seguro de claves\n" +
                "🔑 AES-256: Cifrado simétrico de archivos\n" +
                "🧮 SHA-256: Verificación de integridad\n" +
                "📁 Archivos guardados en: server_files/");
        securityInfoLabel.setFont(Font.font("Arial", 11));
        securityInfoLabel.setTextFill(Color.DARKBLUE);

        section.getChildren().addAll(sectionTitle, securityInfoLabel);
        return section;
    }

    private VBox createLogSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📋 Log de Operaciones Criptográficas");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefRowCount(15);
        logArea.setStyle("-fx-font-family: 'Courier New'; -fx-font-size: 11px;");

        Button clearLogButton = new Button("🗑️ Limpiar Log");
        clearLogButton.setOnAction(e -> {
            logArea.clear();
            logArea.appendText("=== LOG LIMPIADO ===\n\n");
        });

        section.getChildren().addAll(sectionTitle, logArea, clearLogButton);
        return section;
    }

    private Separator createSeparator() {
        Separator sep = new Separator();
        sep.setStyle("-fx-background-color: #e0e0e0;");
        return sep;
    }

    private void startServer() {
        if (serverRunning) return;

        serverRunning = true;
        startButton.setDisable(true);
        stopButton.setDisable(false);

        Platform.runLater(() -> {
            statusLabel.setText("🟢 Servidor activo");
            statusLabel.setTextFill(Color.GREEN);
            connectionInfoLabel.setText("Escuchando en puerto 5555...");
            connectionInfoLabel.setTextFill(Color.BLUE);
            logArea.appendText("🚀 SERVIDOR INICIADO\n");
            logArea.appendText("=" + "=".repeat(40) + "\n");
            logArea.appendText("📡 Escuchando en puerto 5555...\n\n");
        });

        new Thread(() -> {
            try {
                ServerWithProgress.runServer(new ServerProgressCallback() {
                    @Override
                    public void onProgress(String message, double progress) {
                        Platform.runLater(() -> {
                            logArea.appendText(message + "\n");
                            if (progress > 0) {
                                operationProgress.setVisible(true);
                                operationProgress.setProgress(progress);
                            }
                        });
                    }

                    @Override
                    public void onClientConnected(String clientInfo) {
                        Platform.runLater(() -> {
                            connectionInfoLabel.setText("Cliente conectado: " + clientInfo);
                            connectionInfoLabel.setTextFill(Color.BLUE);
                            operationProgress.setVisible(true);
                            operationProgress.setProgress(0.1);
                        });
                    }

                    @Override
                    public void onTransferComplete(boolean success, String message) {
                        Platform.runLater(() -> {
                            if (success) {
                                connectionInfoLabel.setText("✅ " + message);
                                connectionInfoLabel.setTextFill(Color.GREEN);
                                operationProgress.setProgress(1.0);
                                logArea.appendText("\n🎉 " + message + "\n\n");
                            } else {
                                connectionInfoLabel.setText("❌ " + message);
                                connectionInfoLabel.setTextFill(Color.RED);
                                logArea.appendText("\n❌ " + message + "\n\n");
                            }

                            // Reset para próxima conexión
                            new Thread(() -> {
                                try {
                                    Thread.sleep(3000);
                                    Platform.runLater(() -> {
                                        if (serverRunning) {
                                            connectionInfoLabel.setText("Esperando próxima conexión...");
                                            connectionInfoLabel.setTextFill(Color.BLUE);
                                            operationProgress.setVisible(false);
                                            operationProgress.setProgress(0);
                                        }
                                    });
                                } catch (InterruptedException e) {}
                            }).start();
                        });
                    }
                });

            } catch (Exception ex) {
                Platform.runLater(() -> {
                    statusLabel.setText("🔴 Error en servidor");
                    statusLabel.setTextFill(Color.RED);
                    connectionInfoLabel.setText("Error: " + ex.getMessage());
                    connectionInfoLabel.setTextFill(Color.RED);
                    logArea.appendText("❌ ERROR: " + ex.getMessage() + "\n");
                    stopServer();
                });
            }
        }).start();
    }

    private void stopServer() {
        serverRunning = false;
        startButton.setDisable(false);
        stopButton.setDisable(true);

        statusLabel.setText("🔴 Servidor detenido");
        statusLabel.setTextFill(Color.RED);
        connectionInfoLabel.setText("Servidor detenido");
        connectionInfoLabel.setTextFill(Color.GRAY);
        operationProgress.setVisible(false);

        logArea.appendText("⏹️ Servidor detenido por el usuario\n\n");

        new Thread(() -> {
            try {
                ServerWithProgress.stop();
            } catch (IOException e) {
                Platform.runLater(() -> logArea.appendText("❌ Error al detener el servidor: " + e.getMessage() + "\n"));
            }
        }).start();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

interface ServerProgressCallback {
    void onProgress(String message, double progress);
    void onClientConnected(String clientInfo);
    void onTransferComplete(boolean success, String message);
}

class ServerWithProgress {
    private static volatile boolean running = true;
    private static ServerSocket serverSocket;

    public static void stop() throws IOException {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    public static void runServer(ServerProgressCallback callback) throws Exception {
        java.io.File serverDir = new java.io.File("server_files");
        if (!serverDir.exists()) serverDir.mkdirs();

        running = true;

        try {
            serverSocket = new ServerSocket(5555);
            callback.onProgress("📡 Servidor escuchando en puerto 5555...", 0);
            while (running) {
                Socket socket = null;
                try {
                    socket = serverSocket.accept();

                    if (!running){
                        if (socket != null && !socket.isClosed()) {
                            socket.close();
                        }
                        break;
                    }

                    String clientIP = socket.getInetAddress().getHostAddress();
                    callback.onClientConnected(clientIP + ":" + socket.getPort());
                    callback.onProgress("🤝 Cliente conectado desde: " + clientIP, 0.1);

                    java.io.DataInputStream dis = new java.io.DataInputStream(socket.getInputStream());
                    java.io.DataOutputStream dos = new java.io.DataOutputStream(socket.getOutputStream());

                    callback.onProgress("🔐 Generando par de claves RSA-2048...", 0.2);
                    java.security.KeyPair keyPair = crypto.CryptoUtils.generateRSAKeyPair();
                    java.security.PublicKey publicKey = keyPair.getPublic();
                    java.security.PrivateKey privateKey = keyPair.getPrivate();
                    crypto.CryptoUtils.saveKey("server_files/public_key_server.pem", publicKey);
                    callback.onProgress("🔑 Par de claves RSA generado", 0.3);

                    callback.onProgress("📤 Enviando clave pública al cliente...", 0.35);
                    dos.writeInt(publicKey.getEncoded().length);
                    dos.write(publicKey.getEncoded());
                    dos.flush();
                    callback.onProgress("✅ Clave pública enviada", 0.4);

                    callback.onProgress("📥 Recibiendo clave AES cifrada...", 0.5);
                    int aesLen = dis.readInt();
                    byte[] encryptedAES = dis.readNBytes(aesLen);
                    callback.onProgress("🔓 Descifrando clave AES con RSA...", 0.55);
                    byte[] aesKeyBytes = crypto.CryptoUtils.decryptRSA(encryptedAES, privateKey);
                    javax.crypto.SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
                    callback.onProgress("🔑 Clave AES-256 descifrada exitosamente", 0.6);

                    callback.onProgress("📥 Recibiendo archivo cifrado...", 0.7);
                    int fileLen = dis.readInt();
                    byte[] encryptedFile = dis.readNBytes(fileLen);
                    callback.onProgress("🔓 Descifrando archivo con AES-256...", 0.75);
                    byte[] decryptedFile = crypto.CryptoUtils.decryptAES(encryptedFile, aesKey);

                    String fileName = "received_file_" + System.currentTimeMillis() + ".txt";
                    crypto.CryptoUtils.saveToFile("server_files/" + fileName, decryptedFile);
                    callback.onProgress("💾 Archivo descifrado guardado: " + fileName, 0.8);

                    callback.onProgress("📥 Recibiendo hash SHA-256 del cliente...", 0.85);
                    int hashLen = dis.readInt();
                    byte[] clientHash = dis.readNBytes(hashLen);

                    callback.onProgress("🧮 Calculando hash SHA-256 del archivo recibido...", 0.9);
                    byte[] serverHash = crypto.CryptoUtils.sha256(decryptedFile);
                    crypto.CryptoUtils.saveToFile("server_files/hash_servidor.hex", serverHash);

                    callback.onProgress("🔍 Verificando integridad del archivo...", 0.95);
                    boolean integrityOk = java.security.MessageDigest.isEqual(clientHash, serverHash);

                    if (integrityOk) {
                        String successMsg = "Transferencia completada con integridad verificada ✓";
                        callback.onProgress("✅ Integridad verificada: Hashes coinciden", 1.0);
                        callback.onTransferComplete(true, successMsg);
                    } else {
                        String errorMsg = "Error: Integridad fallida - Hashes no coinciden";
                        callback.onProgress("❌ Integridad fallida: Hashes diferentes", 1.0);
                        callback.onTransferComplete(false, errorMsg);
                    }

                    String fileInfo = String.format("📊 Archivo procesado: %s | Tamaño: %s",
                            fileName, formatFileSize(decryptedFile.length));
                    callback.onProgress(fileInfo, 1.0);

                    dis.close();
                    dos.close();
                    socket.close();

                } catch (SocketException se) {
                    callback.onProgress("🛑 Servidor detenido correctamente.", 0);
                    if (socket != null && !socket.isClosed()) {
                        socket.close();
                    }
                    break;
                } catch (Exception e) {
                    if (!running) {
                        callback.onProgress("🛑 Servidor detenido correctamente.", 0);
                        break;
                    }
                    throw e;
                }
            }
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        }
    }

    private static String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }
}