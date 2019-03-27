package sniffer_sun;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import jpcap.*;

import javax.swing.table.DefaultTableModel;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Sniffer extends javax.swing.JFrame{

    public Sniffer() {
        initComponents();
        captureButton.setEnabled(false);
        stopButton.setEnabled(false);
        saveButton.setEnabled(false);
        filter_options1.setEnabled(false);
        filter_options2.setEnabled(false);
        selectButton.setEnabled( false );
    }

    //Globals
    public static NetworkInterface[] NETWORK_INTERFACES;
    public static JpcapCaptor CAP;
    jpcap_thread THREAD;
    public static int INDEX = 0;
    public static int FLAG = 0;
    public static int COUNTER = 0;
    boolean CaptureState = false;
    public static int No = 0;

    JpcapWriter writer = null;
    List<Packet> packetList = new ArrayList<>();

    //HEX-View two functions.
    public static String toHexadecimal(String text) throws UnsupportedEncodingException {
        byte[] myBytes = text.getBytes("UTF-8");

        return DatatypeConverter.printHexBinary(myBytes);
    }

    public static String customizeHexa(String text) {

        String out;
        out = text.replaceAll("(.{32})", "$1\n");
        return out.replaceAll("..(?!$)", "$0 ");
    }

    public void CapturePackets() {

        THREAD = new jpcap_thread() {

            public Object construct() {

                try {

                    CAP = JpcapCaptor.openDevice( NETWORK_INTERFACES[INDEX], 65535, false, 20 );
                    if ( "UDP".equals( filter_options1.getSelectedItem().toString() ) ) {
                        CAP.setFilter( "udp", true );
                    } else if ("TCP".equals(filter_options1.getSelectedItem().toString())) {
                        CAP.setFilter("tcp", true);
                    } else if ("ICMP".equals(filter_options1.getSelectedItem().toString())) {
                        CAP.setFilter("icmp", true);
                    } else if ("ARP".equals(filter_options1.getSelectedItem().toString())) {
                        CAP.setFilter("arp", true);
                    } else if ("IP".equals(filter_options1.getSelectedItem().toString())) {
                        CAP.setFilter("ip", true);
                    }

                    while (CaptureState) {

                        CAP.processPacket(1, new PacketContents());
                        packetList.add(CAP.getPacket());

                    }
                    CAP.close();

                } catch ( Exception e) {
                    System.out.println( e );
                }

                return 0;
            }
            public void finished() {
                this.interrupt();
            }
        };

        THREAD.start();

    }


    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuBar2 = new javax.swing.JMenuBar();
        jMenu2 = new javax.swing.JMenu();
        jMenu3 = new javax.swing.JMenu();
        jMenu4 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jToolBar1 = new javax.swing.JToolBar();
        listButton = new java.awt.Button();
        jLabel1 = new javax.swing.JLabel();
        filter_options1 = new javax.swing.JComboBox<>();
        filter_options2 = new javax.swing.JComboBox<>();
        selectButton = new java.awt.Button();
        captureButton = new java.awt.Button();
        stopButton = new java.awt.Button();
        saveButton = new java.awt.Button();
        jScrollPane4 = new javax.swing.JScrollPane();
        jScrollPane5 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable(){
            public boolean isCellEditable(int row, int column){
                return false;
            }
        };
        jTable2 = new javax.swing.JTable(){
            public boolean isCellEditable(int row, int column){
                return false;
            }
        };
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextArea2 = new javax.swing.JTextArea();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jMenuBar1 = new javax.swing.JMenuBar();

        jMenu2.setText("File");
        jMenuBar2.add(jMenu2);

        jMenu3.setText("Edit");
        jMenuBar2.add(jMenu3);

        jMenu4.setText("jMenu4");

        jMenuItem1.setText("jMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("SUNqing Packet Sniffer");
        setName("SUNqing Packet Sniffer"); // NOI18N

        jToolBar1.setRollover(true);

        listButton.setActionCommand("Choose Interface");
        listButton.setBackground(new java.awt.Color(0, 0, 102));
        listButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        listButton.setForeground(new java.awt.Color(255, 255, 255));
        listButton.setLabel("Choose Interface");
        listButton.setPreferredSize(new java.awt.Dimension(120, 26));
        listButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                listButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(listButton);

        jLabel1.setText(" Filter");
        jToolBar1.add(jLabel1);

        //check before
        filter_options1.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "check before", "TCP", "UDP", "ICMP", "ARP", "IP" }));
        filter_options1.setPreferredSize(new java.awt.Dimension(250, 24));
        filter_options1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filter_optionsActionPerformed(evt);
            }
        });
        jToolBar1.add(filter_options1);

        // check after
        filter_options2.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "check after", "TCP", "UDP", "ICMP", "ARP", "IP" }));
        filter_options2.setPreferredSize(new java.awt.Dimension(240, 24));
        filter_options2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filter_optionsActionPerformed(evt);
            }
        });
        jToolBar1.add(filter_options2);


        selectButton.setBackground(new java.awt.Color( 204, 202, 10 ));
        selectButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        selectButton.setLabel("Select");
        selectButton.setPreferredSize(new java.awt.Dimension(83, 24));
        selectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selectButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(selectButton);


        captureButton.setBackground(new java.awt.Color(0, 204, 0));
        captureButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        captureButton.setLabel("Capture");
        captureButton.setPreferredSize(new java.awt.Dimension(83, 24));
        captureButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                captureButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(captureButton);

        stopButton.setBackground(new java.awt.Color(255, 0, 51));
        stopButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        stopButton.setLabel("Stop");
        stopButton.setPreferredSize(new java.awt.Dimension(83, 24));
        stopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                stopButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(stopButton);

        saveButton.setLabel("Save");
        saveButton.setPreferredSize(new java.awt.Dimension(83, 24));
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(saveButton);

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
                new Object [][] {

                },
                new String [] {
                        "No.", "Length", "Source", "Destination", "Protocol"
                }
        ) {
            Class[] types = new Class [] {
                    Integer.class, Object.class, Object.class, Object.class, String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        jTable1.setRowHeight(15);
        jTable1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jTable1MouseClicked(evt);
            }
        });
        jScrollPane4.setViewportView(jTable1);

        jTable2.setModel(new javax.swing.table.DefaultTableModel(
                new Object [][] {

                },
                new String [] {
                        "Number", "Length", "Source IP", "Destination IP", "Protocol"
                }
        ) {
            Class[] types = new Class [] {
                    Integer.class, Object.class, Object.class, Object.class, String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        jTable2.setRowHeight(10);
        jTable2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jTable1MouseClicked(evt);
            }
        });
        jScrollPane5.setViewportView(jTable2);

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        jScrollPane2.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jTextArea2.setEditable(false);
        jTextArea2.setColumns(20);
        jTextArea2.setRows(5);
        jScrollPane2.setViewportView(jTextArea2);

        jLabel2.setText("Packet information:");

        jLabel3.setText("Hex view:");
        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jScrollPane4)
                        .addComponent(jScrollPane5)
                        .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jScrollPane1)
                        .addComponent(jScrollPane2)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabel2)
                                        .addComponent(jLabel3))
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel3)
                                .addGap(1, 1, 1)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 108, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents


    private void jTable1MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jTable1MouseClicked

        Object obj = jTable1.getModel().getValueAt(jTable1.getSelectedRow(), 0);

        if ( jTable2.getSelectedRow() != -1 ) {
            obj = jTable2.getModel().getValueAt(jTable2.getSelectedRow(), 0);
        }


        if (PacketContents.rowList.get((int) obj)[4] == "TCP") {

            jTextArea1.setText("TCPPacket No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nTCPLength: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nTCPSource IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nTCPDist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nTCPProtocol: " + PacketContents.rowList.get((int) obj)[4]
                    + "\nTCPSource Port: " + PacketContents.rowList.get((int) obj)[5]
                    + "\nTCPDist Port: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nTCPAck: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nTCPAck No: " + PacketContents.rowList.get((int) obj)[8]
                    + "\nTCPData: " + PacketContents.rowList.get((int) obj)[9]
                    + "\nTCPSequence No: " + PacketContents.rowList.get((int) obj)[10]
                    + "\nTCPOffset: " + PacketContents.rowList.get((int) obj)[11]
                    + "\nTCPHeader: " + PacketContents.rowList.get((int) obj)[12]
            );

            try {
                jTextArea2.setText(customizeHexa(toHexadecimal(jTextArea1.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log( Level.SEVERE, null, ex);
            }

        } else if (PacketContents.rowList.get((int) obj)[4] == "UDP") {
            jTextArea1.setText("UDPPacket No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nUDPLength: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nUDPSource IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nUDPDist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nUDPProtocol:" + PacketContents.rowList.get((int) obj)[4]
                    + "\nUDPSource Port: " + PacketContents.rowList.get((int) obj)[5]
                    + "\nUDPDist Port: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nUDPData: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nUDPOffset: " + PacketContents.rowList.get((int) obj)[8]
                    + "\nUDPHeader: " + PacketContents.rowList.get((int) obj)[9]
            );

            try {
                jTextArea2.setText(customizeHexa(toHexadecimal(jTextArea1.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else if (PacketContents.rowList.get((int) obj)[4] == "ICMP") {
            jTextArea1.setText("ICMPPacket No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nICMPLength: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nICMPSource IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nICMPDist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nICMPProtocol:" + PacketContents.rowList.get((int) obj)[4]
                    + "\nICMPChecksum: " + PacketContents.rowList.get((int) obj)[5]
                    + "\nICMPHeader: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nICMPOffset: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nICMPOriginate TimeStamp: " + PacketContents.rowList.get((int) obj)[8] + "bits"
                    + "\nICMPReceive TimeStamp: " + PacketContents.rowList.get((int) obj)[9] + "bits"
                    + "\nICMPTransmit TimeStamp: " + PacketContents.rowList.get((int) obj)[10] + "bits"
                    + "\nICMPData: " + PacketContents.rowList.get((int) obj)[11]
            );

            try {
                jTextArea2.setText(customizeHexa(toHexadecimal(jTextArea1.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else if (PacketContents.rowList.get((int) obj)[5] == "ARP") {
            jTextArea1.setText("Packet No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nARP Sender_hard_addr: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nARP Sender_proto_addr: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nARP Target_hard_addr: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nARP Target_proto_addr:" + PacketContents.rowList.get((int) obj)[4]
                    + "\nARP Hard_type: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nARP Proto_type: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nARP HLen: " + PacketContents.rowList.get((int) obj)[8]
                    + "\nARP PLen: " + PacketContents.rowList.get((int) obj)[9]
                    + "\nARP Operation: " + PacketContents.rowList.get((int) obj)[10]
                    + "\nARP Data: " + PacketContents.rowList.get((int) obj)[11]
            );

            try {
                jTextArea2.setText(customizeHexa(toHexadecimal(jTextArea1.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else if (PacketContents.rowList.get((int) obj)[4] == "IP") {
            jTextArea1.setText("IPPacket No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nIP Length: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nIP Source IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nIP Dist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nIP Protocol: " + PacketContents.rowList.get((int) obj)[4]
                    + "\nIP Version:" + PacketContents.rowList.get((int) obj)[5]
                    + "\nIP Priority: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nIP D_flag: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nIP T_flag: " + PacketContents.rowList.get((int) obj)[8]
                    + "\nIP R_flag: " + PacketContents.rowList.get((int) obj)[9]
                    + "\nIP Rsv_tos: " + PacketContents.rowList.get((int) obj)[10]
                    + "\nIP Rsv_frag: " + PacketContents.rowList.get((int) obj)[11]
                    + "\nIP Dont_frag:" + PacketContents.rowList.get((int) obj)[12]
                    + "\nIP More_frag: " + PacketContents.rowList.get((int) obj)[13]
                    + "\nIP Offset: " + PacketContents.rowList.get((int) obj)[14]
                    + "\nIP Hop_limit: " + PacketContents.rowList.get((int) obj)[15]
                    + "\nIP Protocol: " + PacketContents.rowList.get((int) obj)[16]
                    + "\nIP Ident: " + PacketContents.rowList.get((int) obj)[17]
                    + "\nIP Flow_label: " + PacketContents.rowList.get((int) obj)[18]
                    + "\nIP Option: " + PacketContents.rowList.get((int) obj)[19]
                    + "\nIP Data: " + PacketContents.rowList.get((int) obj)[20]
            );

            try {
                jTextArea2.setText(customizeHexa(toHexadecimal(jTextArea1.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

    }//GEN-LAST:event_jTable1MouseClicked

    private void selectButtonActionPerformed(java.awt.event.ActionEvent evt) {

        CaptureState = false;
        THREAD.finished();
        saveButton.setEnabled(true);
        filter_options1.setEnabled(false);
        filter_options2.setEnabled(true);
        listButton.setEnabled(true);


        DefaultTableModel model_select = (DefaultTableModel) Sniffer.jTable2.getModel();

        for (int j = 0; j < number_Counter; j++) {

            model_select.removeRow( 0 );

        }

        if ( "ARP".equals( filter_options2.getSelectedItem().toString() ) ) {

            Object[] row_top = {"ARP", "sender_hardaddr", "sender_protoaddr", "target_hardaddr", "target_protoaddr"};
            model_select.addRow(row_top);

        }

        number_Counter = 0;

        for (int i = 0; i < PacketContents.rowList.size(); i++){

            Object length = PacketContents.rowList.get( i )[1];
            Object src_ip = PacketContents.rowList.get( i )[2];
            Object dst_ip = PacketContents.rowList.get( i )[3];

            if ( "UDP".equals( filter_options2.getSelectedItem().toString() ) ){

                if ( "UDP".equals( PacketContents.rowList.get( i )[4] ) ) {

                    Object[] row = {number_Counter, length, src_ip, dst_ip, "UDP"};
                    model_select.addRow(row);
                    number_Counter += 1;
                }

            } else if ( "TCP".equals( filter_options2.getSelectedItem().toString() ) ) {

                if ( "TCP".equals( PacketContents.rowList.get( i )[4] ) ) {

                    Object[] row = {number_Counter, length, src_ip, dst_ip, "TCP"};
                    model_select.addRow(row);
                    number_Counter += 1;
                }

            } else if ( "ICMP".equals( filter_options2.getSelectedItem().toString() ) ) {

                if ( "ICMP".equals( PacketContents.rowList.get( i )[4] ) ) {

                    Object[] row = {number_Counter, length, src_ip, dst_ip, "ICMP"};
                    model_select.addRow(row);
                    number_Counter += 1;
                }

            } else if ( "IP".equals( filter_options2.getSelectedItem().toString() ) ) {

                if ( "UDP".equals( PacketContents.rowList.get( i )[4] ) ) {

                    Object[] row = {number_Counter, length, src_ip, dst_ip, "UDP"};
                    model_select.addRow(row);
                    number_Counter += 1;

                } else if ( "TCP".equals( PacketContents.rowList.get( i )[4] ) ) {

                    Object[] row = {number_Counter, length, src_ip, dst_ip, "TCP"};
                    model_select.addRow(row);
                    number_Counter += 1;

                }

            } else if ( "ARP".equals( filter_options2.getSelectedItem().toString() ) ) {

                if ( "ARP".equals( PacketContents.rowList.get( i )[5] ) ) {

                    Object target_hardaddr = PacketContents.rowList.get( i )[3];
                    Object target_protoaddr = PacketContents.rowList.get( i )[4];
                    Object sender_hardaddr = PacketContents.rowList.get( i )[1];
                    Object sender_protoaddr = PacketContents.rowList.get( i )[2];

                    Object[] row = {number_Counter, sender_hardaddr, sender_protoaddr, target_hardaddr, target_protoaddr};
                    model_select.addRow(row);
                    number_Counter += 1;
                }

            }

        }

    }//GEN-LAST:event_selectButtonActionPerformed

    private void captureButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_captureButtonActionPerformed

        CaptureState = true;
        CapturePackets();
        saveButton.setEnabled(false);
        filter_options1.setEnabled(false);
        filter_options2.setEnabled(false);
        listButton.setEnabled(false);
        selectButton.setEnabled( false );
    }//GEN-LAST:event_captureButtonActionPerformed

    private void stopButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_stopButtonActionPerformed

        CaptureState = false;
        THREAD.finished();
        saveButton.setEnabled(true);
        filter_options1.setEnabled(true);
        filter_options2.setEnabled(true);
        listButton.setEnabled(true);
        selectButton.setEnabled( true );
    }//GEN-LAST:event_stopButtonActionPerformed

    private void listButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_listButtonActionPerformed

        sniffer_sun.InterfacesWindow nw = new InterfacesWindow();
    }//GEN-LAST:event_listButtonActionPerformed

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed

        writer = null;
        try {
            CAP = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, false, 20);

            writer = JpcapWriter.openDumpFile(CAP, "captured_data.txt");
        } catch (IOException ex) {
            //    Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
        }

        for (int i = 0; i < No; i++) {
            writer.writePacket(packetList.get(i));
        }
        writer.close();


    }//GEN-LAST:event_saveButtonActionPerformed

    private void filter_optionsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_filter_optionsActionPerformed

    }//GEN-LAST:event_filter_optionsActionPerformed

    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Sniffer.class.getName()).log( Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            Logger.getLogger(Sniffer.class.getName()).log( Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            Logger.getLogger(Sniffer.class.getName()).log( Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            Logger.getLogger(Sniffer.class.getName()).log( Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Sniffer().setVisible(true);
            }
        });
    }






    // Variables declaration - do not modify//GEN-BEGIN:variables
    public static java.awt.Button captureButton;
    public static javax.swing.JComboBox<String> filter_options1;
    public static javax.swing.JComboBox<String> filter_options2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuBar jMenuBar2;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    public static javax.swing.JTable jTable1;
    public static javax.swing.JTable jTable2;
    public static javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextArea jTextArea2;
    private javax.swing.JToolBar jToolBar1;
    public static java.awt.Button selectButton;
    public static java.awt.Button listButton;
    public static java.awt.Button saveButton;
    public static java.awt.Button stopButton;
    public static int number_Counter;
    // End of variables declaration//GEN-END:variables

}

