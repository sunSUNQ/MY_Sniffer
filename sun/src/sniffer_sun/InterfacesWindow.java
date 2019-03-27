package sniffer_sun;

import com.sun.glass.events.KeyEvent;
import javax.swing.*;
import jpcap.*;


public class InterfacesWindow extends JFrame {

    public InterfacesWindow() {
        initComponents();
        ListNetworkInterfaces();
        textField1.requestFocus();
        setVisible(true);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    public void ListNetworkInterfaces() {

        Sniffer.NETWORK_INTERFACES = JpcapCaptor.getDeviceList();
        jTextArea1.setText("");
        for (int i = 0; i < Sniffer.NETWORK_INTERFACES.length; i++) {
            jTextArea1.append(
                    "\n\n-----------------------------------------------------------------------Interface (" + i
                    + ") -----------------------------------------------------------------------");
            jTextArea1.append("\nInterface Number:   " + i);
            jTextArea1.append("\nDescription:              "
                    + Sniffer.NETWORK_INTERFACES[i].name + "("
                    + Sniffer.NETWORK_INTERFACES[i].description + ")");
            jTextArea1.append("\nDatalink Name:         "
                    + Sniffer.NETWORK_INTERFACES[i].datalink_name + "("
                    + Sniffer.NETWORK_INTERFACES[i].datalink_description + ")");
            jTextArea1.append("\nMac Address:            ");

            byte[] R = Sniffer.NETWORK_INTERFACES[i].mac_address;
            for (int A = 0; A < Sniffer.NETWORK_INTERFACES.length; A++) {
                jTextArea1.append(Integer.toHexString(R[A] & 0xff) + ":");
            }

            NetworkInterfaceAddress[] INT = Sniffer.NETWORK_INTERFACES[i].addresses;
            jTextArea1.append("\nIP Address:                " + INT[0].address);
            jTextArea1.append("\nSubnet Mask:            " + INT[0].subnet);
            jTextArea1.append("\nBroadcast Address: " + INT[0].broadcast);

            Sniffer.COUNTER++;
        }
    }

    public void ChooseInterface() {

        int TEMP = Integer.parseInt(textField1.getText());

        if (TEMP > -1 && TEMP < Sniffer.COUNTER) {
            Sniffer.INDEX = TEMP;
            Sniffer.captureButton.setEnabled(true);
            Sniffer.filter_options1.setEnabled(true);
            Sniffer.filter_options2.setEnabled(true);
            Sniffer.stopButton.setEnabled(true);
            Sniffer.saveButton.setEnabled(true);
        } else {
            JOptionPane.showMessageDialog(null, "Outside the RANGE. # interfaces = 0-" + (Sniffer.COUNTER - 1) + ".");
            InterfacesWindow nw = new InterfacesWindow();

        }

        textField1.setText("");

    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new JScrollPane();
        jTextArea1 = new JTextArea();
        jButton1 = new JButton();
        textField1 = new java.awt.TextField();
        jLabel1 = new JLabel();

        setDefaultCloseOperation( WindowConstants.EXIT_ON_CLOSE);
        setTitle("Interfaces List");
        setName("Interfaces list"); // NOI18N

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        jButton1.setText("Select");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        textField1.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                textField1KeyPressed(evt);
            }
        });

        jLabel1.setText("Please select the interface number!");

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup( GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup( GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 249, Short.MAX_VALUE)
                        .addComponent(jLabel1, GroupLayout.PREFERRED_SIZE, 224, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap( LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(textField1, GroupLayout.PREFERRED_SIZE, 70, GroupLayout.PREFERRED_SIZE)
                        .addGap(47, 47, 47)
                        .addComponent(jButton1, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane1))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup( GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, GroupLayout.PREFERRED_SIZE, 352, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap( LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup( GroupLayout.Alignment.LEADING)
                    .addComponent(textField1, GroupLayout.Alignment.TRAILING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton1, GroupLayout.Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, 33, GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        ChooseInterface();
        setVisible(false);
    }//GEN-LAST:event_jButton1ActionPerformed

    private void textField1KeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_textField1KeyPressed

        if (evt.getExtendedKeyCode() == KeyEvent.VK_ENTER) {
            ChooseInterface();
            setVisible(false);
        }
    }//GEN-LAST:event_textField1KeyPressed

    public static void main(String args[]) {

        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger( InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger( InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger( InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger( InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }


        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new InterfacesWindow().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private JButton jButton1;
    private JLabel jLabel1;
    private JScrollPane jScrollPane1;
    private JTextArea jTextArea1;
    private java.awt.TextField textField1;
    // End of variables declaration//GEN-END:variables
}
