import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptionApp {

    private JTextArea t1e, t1d, t2e, t2d;
    private JButton encryptButton, decryptButton, changeEncryptMethodButton, changeDecryptMethodButton;

    private SecretKey secretKey; // Key for encryption and decryption

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new EncryptionApp().createAndShowGUI());
    }

    private void createAndShowGUI() {
        JFrame frame = new JFrame("Encryption App");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Create components
        t1e = new JTextArea(5, 20);
        t1d = new JTextArea(5, 20);
        t2e = new JTextArea(5, 20);
        t2d = new JTextArea(5, 20);
        t2e.setEditable(false);
        t2d.setEditable(false);

        encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                encrypt();
            }
        });

        decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                decrypt();
            }
        });

        changeEncryptMethodButton = new JButton("Change Encrypt Method");
        changeEncryptMethodButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Add logic for changing encryption method if needed
                JOptionPane.showMessageDialog(frame, "Change Encrypt Method clicked!");
            }
        });

        changeDecryptMethodButton = new JButton("Change Decrypt Method");
        changeDecryptMethodButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Add logic for changing decryption method if needed
                JOptionPane.showMessageDialog(frame, "Change Decrypt Method clicked!");
            }
        });

        // Set layout
        GroupLayout layout = new GroupLayout(frame.getContentPane());
        frame.getContentPane().setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(new JScrollPane(t1e))
                                .addComponent(new JScrollPane(t2e))
                                .addComponent(encryptButton)
                                .addComponent(changeEncryptMethodButton))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(new JScrollPane(t1d))
                                .addComponent(new JScrollPane(t2d))
                                .addComponent(decryptButton)
                                .addComponent(changeDecryptMethodButton))));

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(new JScrollPane(t1e))
                        .addComponent(new JScrollPane(t1d)))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(new JScrollPane(t2e))
                        .addComponent(new JScrollPane(t2d)))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(encryptButton)
                        .addComponent(decryptButton))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(changeEncryptMethodButton)
                        .addComponent(changeDecryptMethodButton)));

        // Pack and display the frame
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        // Generate a secret key for encryption and decryption
        try {
            secretKey = generateSecretKey();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private void encrypt() {
        try {
            String plainText = t1e.getText();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            t2e.setText(Base64.getEncoder().encodeToString(encryptedBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void decrypt() {
        try {
            String encryptedText = t1d.getText();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            t2d.setText(new String(decryptedBytes, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
