package com.mycompany.fileencryptionapp;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import static javax.swing.WindowConstants.EXIT_ON_CLOSE;
public class FileEncryptionApp extends JFrame {
    private JTextArea textArea;
    private UserManager userManager;
    private boolean loggedIn;
    private List<String> encryptedFiles;
    private BackgroundPanel backgroundPanel;
    private JLabel logoLabel;

    public FileEncryptionApp() {
        setTitle("File Encryption/Decryption/Hashing App");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        textArea = new JTextArea();
        JScrollPane scrollPane = new JScrollPane(textArea);
        backgroundPanel = new BackgroundPanel();
        backgroundPanel.setLayout(new BorderLayout());

        // Load the logo image
        ImageIcon logoIcon = new ImageIcon("src/rm373batch4-15.jpg");
        logoLabel = new JLabel(logoIcon);

        // Add the logo label to the background panel
        backgroundPanel.add(logoLabel, BorderLayout.NORTH);
        JButton encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (loggedIn) {
                    encryptFile();
                } else {
                    showLoginMessage();
                }
            }
        });

        JButton decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (loggedIn) {
                    decryptFile();
                } else {
                    showLoginMessage();
                }
            }
        });

        JButton hashButton = new JButton("Hash");
        hashButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (loggedIn) {
                    hashFile();
                } else {
                    showLoginMessage();
                }
            }
        });

        JButton loginButton = new JButton("Login");
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showLoginDialog();
            }
        });

        JButton registerButton = new JButton("Register");
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showRegisterDialog();
            }
        });

        JButton showFilesButton = new JButton("Show Files");
        showFilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (loggedIn) {
                    showEncryptedFiles();
                } else {
                    showLoginMessage();
                }
            }
        });

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        buttonPanel.add(hashButton);
        buttonPanel.add(loginButton);
        buttonPanel.add(registerButton);
        buttonPanel.add(showFilesButton);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(scrollPane, BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);

        userManager = new UserManager();
        loggedIn = false;
        encryptedFiles = new ArrayList<>();
    }

    private void showEncryptedFiles() {
        textArea.append("Encrypted Files:\n");
        for (String filePath : encryptedFiles) {
            textArea.append(filePath + "\n");
        }
    }

    private void showLoginMessage() {
        JOptionPane.showMessageDialog(this, "Please login to perform this operation.", "Login Required", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showRegisterMessage() {
        JOptionPane.showMessageDialog(this, "User registration successful. You can now login.", "Registration Successful", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showErrorMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private void showLoginDialog() {
        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        Object[] message = {
                "Username:", usernameField,
                "Password:", passwordField
        };
        int option = JOptionPane.showConfirmDialog(this, message, "Login", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            login(username, password);
        }
    }

    private void showRegisterDialog() {
        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        Object[] message = {
                "Username:", usernameField,
                "Password:", passwordField
        };
        int option = JOptionPane.showConfirmDialog(this, message, "Register", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            register(username, password);
        }
    }

    private void login(String username, String password) {
        if (userManager.authenticateUser(username, password)) {
            loggedIn = true;
            textArea.append("Login successful.\n");
        } else {
            loggedIn = false;
            showErrorMessage("Invalid username or password.");
        }
    }

    private void register(String username, String password) {
        if (userManager.registerUser(username, password)) {
            showRegisterMessage();
        } else {
            showErrorMessage("Username already taken.");
        }
    }

    private void encryptFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile();

            try {
                String outputPath = inputFile.getParent()  + File.separator + "encrypted." + inputFile.getName() ;
                File outputFile = new File(outputPath);
                encryptedFiles.add(outputFile.getAbsolutePath());
                String password = "MySecretPassword";
                byte[] salt = new byte[16];
                // Generate random salt
                new java.security.SecureRandom().nextBytes(salt);

                SecretKey secretKey = generateSecretKey(password, salt);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);

                // Generate initialization vector (IV)
                byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

                FileOutputStream outputStream = new FileOutputStream(outputFile);
                outputStream.write(salt);
                outputStream.write(iv);

                CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

                FileInputStream inputStream = new FileInputStream(inputFile);

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    cipherOutputStream.write(buffer, 0, bytesRead);
                }

                inputStream.close();
                cipherOutputStream.close();
                outputStream.close();
                downloadFile(outputFile);
                textArea.append("File encrypted successfully.\n");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | InvalidParameterSpecException ex) {
                ex.printStackTrace();
                textArea.append("Error encrypting file.\n");
            }
        }
    }


    private void decryptFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile();

            try {
                String outputPath = inputFile.getParent()  + File.separator  + "decrypted." +  inputFile.getName();
                File outputFile = new File(outputPath);
                encryptedFiles.add(outputFile.getAbsolutePath());
                FileInputStream inputStream = new FileInputStream(inputFile);

                byte[] salt = new byte[16];
                inputStream.read(salt);

                byte[] iv = new byte[16];
                inputStream.read(iv);

                String password = "MySecretPassword";
                SecretKey secretKey = generateSecretKey(password, salt);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
                FileOutputStream outputStream = new FileOutputStream(outputFile);

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }

                cipherInputStream.close();
                outputStream.close();
                inputStream.close();
                downloadFile(outputFile);
                textArea.append("File decrypted successfully.\n");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                    IOException | InvalidAlgorithmParameterException ex) {
                ex.printStackTrace();
                textArea.append("Error decrypting file.\n");
            }
        }
    }

    private void hashFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile();

            try {
                FileInputStream inputStream = new FileInputStream(inputFile);
                MessageDigest md = MessageDigest.getInstance("SHA-256");

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesRead);
                }

                inputStream.close();

                byte[] hashBytes = md.digest();

                StringBuilder hash = new StringBuilder();
                for (byte b : hashBytes) {
                    hash.append(String.format("%02x", b));
                }

                textArea.append("File hash: " + hash.toString() + "\n");

                String outputPath = inputFile.getParent()  + File.separator + "hash." + inputFile.getName() ;
                File hashFile = new File(outputPath);
                FileWriter writer = new FileWriter(hashFile);
                writer.write(hash.toString());
                writer.close();
                encryptedFiles.add(hashFile.getAbsolutePath());
                downloadFile(hashFile);
            } catch (IOException | NoSuchAlgorithmException ex) {
                ex.printStackTrace();
                textArea.append("Error hashing file.\n");
            }
        }
    }


    private void downloadFile(File file) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(file);
        int returnValue = fileChooser.showSaveDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();

            try {
                Files.copy(file.toPath(), selectedFile.toPath());
                textArea.append("File downloaded successfully.\n");
            } catch (IOException ex) {
                ex.printStackTrace();
                textArea.append("Error downloading file.\n");
            }
        }
    }


    private SecretKey generateSecretKey(String password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                FileEncryptionApp app = new FileEncryptionApp();
                app.setVisible(true);
            }
        });
    }
}

