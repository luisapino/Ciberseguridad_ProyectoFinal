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
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ServerApp extends Application {
    private TextArea logArea;
    private Label statusLabel;
    private Label connectionInfoLabel;
    private Label securityInfoLabel;
    private Button startButton;
    private Button stopButton;
    private Button viewFilesButton;
    private ProgressBar operationProgress;
    private ListView<String> fileListView;
    private TextArea fileContentArea;
    private boolean serverRunning = false;

    @Override
    public void start(Stage stage) {
        stage.setTitle("🛡️ Servidor - Transferencia Segura de Archivos");

        Label titleLabel = new Label("Servidor de Transferencia Segura");
        titleLabel.setFont(Font.font("Arial", FontWeight.BOLD, 18));
        titleLabel.setTextFill(Color.web("#251605"));

        VBox controlSection = createControlSection();
        VBox statusSection = createStatusSection();
        VBox securitySection = createSecuritySection();
        VBox filesViewSection = createFilesViewSection();
        VBox logSection = createLogSection();

        VBox root = new VBox(15);
        root.setPadding(new Insets(20));
        root.setStyle("-fx-background-color: #D9DCE7;");

        root.getChildren().addAll(
                titleLabel,
                createSeparator(),
                controlSection,
                createSeparator(),
                statusSection,
                createSeparator(),
                securitySection,
                createSeparator(),
                filesViewSection,
                createSeparator(),
                logSection
        );

        Scene scene = new Scene(new ScrollPane(root), 500, 900);
        stage.setScene(scene);
        stage.show();

        logArea.appendText("=== SERVIDOR DE TRANSFERENCIA SEGURA ===\n");
        logArea.appendText("🔐 Protocolo: RSA-2048 + AES-256 + SHA-256\n");
        logArea.appendText("📡 Puerto: 5555\n");
        logArea.appendText("🛡️ Verificación de integridad: SHA-256\n");
        logArea.appendText("📁 Archivos guardados en: server_files/\n");
        logArea.appendText("Estado: Listo para iniciar...\n\n");
    }

    private VBox createControlSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color:#ffffff; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("⚙️ Control del Servidor");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        startButton = new Button("🚀 Iniciar Servidor");
        startButton.setStyle("-fx-background-color:#2E8B57; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
        startButton.setPrefWidth(200);
        startButton.setOnAction(e -> startServer());

        stopButton = new Button("⏹️ Detener Servidor");
        stopButton.setStyle("-fx-background-color:#AB2247; -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14px;");
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
        operationProgress.setStyle("-fx-accent: #8AEDC9;");
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
                "📁 Archivos guardados en: server_files/\n");
        securityInfoLabel.setFont(Font.font("Arial", 11));
        securityInfoLabel.setTextFill(Color.DARKBLUE);

        section.getChildren().addAll(sectionTitle, securityInfoLabel);
        return section;
    }

    private VBox createFilesViewSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📂 Archivos Criptográficos del Servidor");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        viewFilesButton = new Button("🔍 Ver Archivos del Servidor");
        viewFilesButton.setStyle("-fx-background-color: #6A5ACD; -fx-text-fill: white; -fx-font-weight: bold;");
        viewFilesButton.setOnAction(e -> refreshFileList());

        Button openFolderButton = new Button("📁 Abrir Carpeta server_files");
        openFolderButton.setStyle("-fx-background-color: #2E8B57; -fx-text-fill: white; -fx-font-weight: bold;");
        openFolderButton.setOnAction(e -> openServerFolder());

        HBox buttonBox = new HBox(10, viewFilesButton, openFolderButton);

        // Lista de archivos
        fileListView = new ListView<>();
        fileListView.setPrefHeight(120);
        fileListView.setOnMouseClicked(e -> {
            if (e.getClickCount() == 2) {
                showFileContent();
            }
        });

        Label instructionLabel = new Label("💡 Doble clic en un archivo para ver su contenido");
        instructionLabel.setFont(Font.font("Arial", 10));
        instructionLabel.setTextFill(Color.GRAY);

        // Área para mostrar contenido del archivo
        fileContentArea = new TextArea();
        fileContentArea.setEditable(false);
        fileContentArea.setPrefRowCount(6);
        fileContentArea.setStyle("-fx-font-family: 'Courier New'; -fx-font-size: 10px;");
        fileContentArea.setPromptText("Selecciona un archivo para ver su contenido...");

        section.getChildren().addAll(sectionTitle, buttonBox, fileListView, instructionLabel, 
                                   new Label("📄 Contenido del Archivo:"), fileContentArea);
        return section;
    }

    private VBox createLogSection() {
        VBox section = new VBox(10);
        section.setStyle("-fx-background-color: white; -fx-padding: 15; -fx-background-radius: 5;");

        Label sectionTitle = new Label("📋 Log de Operaciones Criptográficas Servidor");
        sectionTitle.setFont(Font.font("Arial", FontWeight.BOLD, 14));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefRowCount(15);
        logArea.setStyle("-fx-font-family: 'Courier New'; -fx-font-size: 11px;");

        Button clearLogButton = new Button("Limpiar Log");
        clearLogButton.setOnAction(e -> {
            logArea.clear();
            logArea.appendText("=== LOG LIMPIADO ===\n\n");
        });
        clearLogButton.setStyle(
            "-fx-background-color: #BB4D69;" + 
            "-fx-text-fill: white;" +         
            "-fx-font-weight: bold;"
        );

        section.getChildren().addAll(sectionTitle, logArea, clearLogButton);
        return section;
    }

    private Separator createSeparator() {
        Separator sep = new Separator();
        sep.setStyle("-fx-background-color: #AB2247;");
        return sep;
    }

    private void refreshFileList() {
        ObservableList<String> files = FXCollections.observableArrayList();
        File serverDir = new File("server_files");
        
        if (!serverDir.exists()) {
            serverDir.mkdirs();
            files.add("📁 Carpeta server_files creada - No hay archivos aún");
        } else {
            File[] fileArray = serverDir.listFiles();
            if (fileArray != null && fileArray.length > 0) {
                SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                for (File file : fileArray) {
                    if (file.isFile()) {
                        String fileType = getFileTypeIcon(file.getName());
                        String fileInfo = String.format("%s %s (%s) - %s", 
                            fileType, 
                            file.getName(), 
                            formatFileSize(file.length()),
                            sdf.format(new Date(file.lastModified()))
                        );
                        files.add(fileInfo);
                    }
                }
            } else {
                files.add("📁 Carpeta vacía - No hay archivos procesados aún");
            }
        }
        
        fileListView.setItems(files);
        logArea.appendText("🔍 Lista de archivos del servidor actualizada (" + (files.size()) + " elementos)\n");
    }

    private String getFileTypeIcon(String fileName) {
        if (fileName.contains("public_key")) return "🔑";
        if (fileName.contains("private_key")) return "🔑";
        if (fileName.contains("aes_key_recibida")) return "🔐";
        if (fileName.contains("received_file")) return "📄";
        if (fileName.contains("hash_cliente")) return "🔍";
        if (fileName.contains("hash_servidor")) return "🔍";
        if (fileName.contains("cifrado") || fileName.contains("encrypted")) return "🔒";
        if (fileName.contains("decrypted")) return "🔓";
        return "📎";
    }

    private void showFileContent() {
        String selectedItem = fileListView.getSelectionModel().getSelectedItem();
        if (selectedItem == null || selectedItem.startsWith("📁")) {
            return;
        }

        // Extraer el nombre del archivo de la cadena formateada
        String fileName = selectedItem.split(" ")[1];
        File file = new File("server_files/" + fileName);

        if (!file.exists()) {
            fileContentArea.setText("❌ Archivo no encontrado: " + fileName);
            return;
        }

        try {
            byte[] content = Files.readAllBytes(file.toPath());
            String displayContent;

            if (fileName.endsWith(".pem")) {
                // Mostrar archivos PEM como texto
                displayContent = new String(content);
            } else if (fileName.endsWith(".hex")) {
                // Mostrar archivos hex como hexadecimal
                displayContent = "Contenido hexadecimal:\n" + bytesToHex(content);
            } else if (fileName.endsWith(".bin")) {
                // Mostrar archivos binarios como hex
                displayContent = "Archivo binario (hex):\n" + bytesToHex(content);
                if (content.length > 200) {
                    displayContent += "\n\n... (mostrando primeros 200 bytes de " + content.length + " totales)";
                }
            } else {
                // Intentar mostrar como texto
                try {
                    displayContent = new String(content);
                } catch (Exception e) {
                    displayContent = "Archivo binario (hex):\n" + bytesToHex(content);
                }
            }

            String header = String.format("📄 %s (%s)\n%s\n\n", 
                fileName, formatFileSize(content.length), "=".repeat(50));
            fileContentArea.setText(header + displayContent);

        } catch (Exception e) {
            fileContentArea.setText("❌ Error al leer archivo: " + e.getMessage());
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        int maxBytes = Math.min(bytes.length, 200);
        
        for (int i = 0; i < maxBytes; i++) {
            if (i > 0 && i % 16 == 0) {
                result.append("\n");
            }
            result.append(String.format("%02X ", bytes[i]));
        }
        
        if (bytes.length > maxBytes) {
            result.append("\n... (").append(bytes.length - maxBytes).append(" bytes más)");
        }
        
        return result.toString();
    }

    private void openServerFolder() {
        try {
            File serverDir = new File("server_files");
            if (!serverDir.exists()) {
                serverDir.mkdirs();
            }
            
            // Intentar abrir el explorador de archivos
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                Runtime.getRuntime().exec("explorer " + serverDir.getAbsolutePath());
            } else if (System.getProperty("os.name").toLowerCase().contains("mac")) {
                Runtime.getRuntime().exec("open " + serverDir.getAbsolutePath());
            } else {
                // Linux
                Runtime.getRuntime().exec("xdg-open " + serverDir.getAbsolutePath());
            }
            logArea.appendText("📁 Abriendo carpeta server_files...\n");
        } catch (Exception e) {
            logArea.appendText("❌ Error al abrir carpeta: " + e.getMessage() + "\n");
            showAlert("Error", "No se pudo abrir la carpeta: " + e.getMessage());
        }
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
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

                            // Auto-refresh file list after transfer
                            refreshFileList();

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
                    
                    // Guardar ambas claves (pública y privada)
                    crypto.CryptoUtils.saveKey("server_files/public_key_server.pem", publicKey);
                    crypto.CryptoUtils.saveKey("server_files/private_key_server.pem", privateKey);
                    callback.onProgress("🔑 Par de claves RSA generado y guardado", 0.3);

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
                    
                    // Guardar la clave AES recibida del cliente (descifrada)
                    crypto.CryptoUtils.saveToFile("server_files/aes_key_recibida_cliente.hex", aesKeyBytes);
                    callback.onProgress("🔑 Clave AES-256 descifrada y guardada", 0.6);

                    callback.onProgress("📥 Recibiendo archivo cifrado...", 0.7);
                    int fileLen = dis.readInt();
                    byte[] encryptedFile = dis.readNBytes(fileLen);
                    
                    // Guardar el archivo cifrado tal como llegó del cliente
                    crypto.CryptoUtils.saveToFile("server_files/archivo_cifrado_recibido_cliente.bin", encryptedFile);
                    callback.onProgress("💾 Archivo cifrado del cliente guardado", 0.72);
                    
                    callback.onProgress("🔓 Descifrando archivo con AES-256...", 0.75);
                    byte[] decryptedFile = crypto.CryptoUtils.decryptAES(encryptedFile, aesKey);

                    String fileName = "received_file_" + System.currentTimeMillis() + ".txt";
                    crypto.CryptoUtils.saveToFile("server_files/" + fileName, decryptedFile);
                    callback.onProgress("💾 Archivo descifrado guardado: " + fileName, 0.8);

                    callback.onProgress("📥 Recibiendo hash SHA-256 del cliente...", 0.85);
                    int hashLen = dis.readInt();
                    byte[] clientHash = dis.readNBytes(hashLen);
                    
                    // Guardar el hash que llegó del cliente
                    crypto.CryptoUtils.saveToFile("server_files/hash_cliente_recibido.hex", clientHash);
                    callback.onProgress("💾 Hash del cliente guardado", 0.87);

                    callback.onProgress("🧮 Calculando hash SHA-256 del archivo recibido...", 0.9);
                    byte[] serverHash = crypto.CryptoUtils.sha256(decryptedFile);
                    crypto.CryptoUtils.saveToFile("server_files/hash_servidor_calculado.hex", serverHash);

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
                    
                    // Resumen de archivos guardados
                    callback.onProgress("📁 ARCHIVOS GUARDADOS EN server_files/:", 1.0);
                    callback.onProgress("  🔑 public_key_server.pem (clave pública RSA)", 1.0);
                    callback.onProgress("  🗝️ private_key_server.pem (clave privada RSA)", 1.0);
                    callback.onProgress("  🔐 aes_key_recibida_cliente.hex (clave AES del cliente)", 1.0);
                    callback.onProgress("  🔒 archivo_cifrado_recibido_cliente.bin (archivo cifrado)", 1.0);
                    callback.onProgress("  📥 " + fileName + " (archivo descifrado)", 1.0);
                    callback.onProgress("  🧮 hash_cliente_recibido.hex (hash del cliente)", 1.0);
                    callback.onProgress("  🔍 hash_servidor_calculado.hex (hash calculado por servidor)", 1.0);

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