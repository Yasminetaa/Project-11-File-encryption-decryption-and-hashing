package com.mycompany.fileencryptionapp;

import java.awt.Graphics;
import java.awt.Image;
import javax.swing.ImageIcon;
import javax.swing.JPanel;

public class BackgroundPanel extends JPanel {
    private Image backgroundImg;

    public BackgroundPanel() {
        // Load the background image
        backgroundImg = new ImageIcon("C:\\Users\\USER\\Desktop\\file\\src\\rm373batch4-15.jpg").getImage();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);

        // Paint the background image
        g.drawImage(backgroundImg, 0, 0, getWidth(), getHeight(), this);
    }
}