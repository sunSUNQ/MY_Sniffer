package sniffer_sun;

import jpcap.PacketReceiver;
import jpcap.packet.*;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

public class PacketContents implements PacketReceiver {

    public static TCPPacket tcp;
    public static UDPPacket udp;
    public static ICMPPacket icmp;
    public static ARPPacket arp;
    public static IPPacket ip;

    public static List<Object[]> rowList = new ArrayList<Object[]>();



    @Override
    public void receivePacket(Packet packet) {

        if (packet instanceof TCPPacket) {
            tcp = (TCPPacket) packet;

            Object[] row = {Sniffer.No, tcp.length, tcp.src_ip, tcp.dst_ip, "TCP"};

            rowList.add(new Object[]{Sniffer.No, tcp.length, tcp.src_ip, tcp.dst_ip, "TCP", tcp.src_port, tcp.dst_port,
                tcp.ack, tcp.ack_num, tcp.data, tcp.sequence, tcp.offset, tcp.header});

            DefaultTableModel model = (DefaultTableModel) Sniffer.jTable1.getModel();
            model.addRow(row);
            Sniffer.No++;

        } else if (packet instanceof UDPPacket) {

            udp = (UDPPacket) packet;

            Object[] row = {Sniffer.No, udp.length, udp.src_ip, udp.dst_ip, "UDP"};
            rowList.add(new Object[]{Sniffer.No, udp.length, udp.src_ip, udp.dst_ip, "UDP", udp.src_port, udp.dst_port,
                udp.data, udp.offset, udp.header});

            DefaultTableModel model = (DefaultTableModel) Sniffer.jTable1.getModel();
            model.addRow(row);
            Sniffer.No++;

        } else if (packet instanceof ICMPPacket) {

            icmp = (ICMPPacket) packet;

            Object[] row = {Sniffer.No, icmp.length, icmp.src_ip, icmp.dst_ip, "ICMP"};
            rowList.add(new Object[]{Sniffer.No, icmp.length, icmp.src_ip, icmp.dst_ip, "ICMP", icmp.checksum, icmp.header,
                icmp.offset, icmp.orig_timestamp, icmp.recv_timestamp, icmp.trans_timestamp, icmp.data});

            DefaultTableModel model = (DefaultTableModel) Sniffer.jTable1.getModel();
            model.addRow(row);
            Sniffer.No++;

        } else if (packet instanceof ARPPacket) {

            arp = (ARPPacket) packet;

            Object[] row = {Sniffer.No, arp.sender_hardaddr, arp.sender_protoaddr, arp.target_hardaddr, "ARP" };
            rowList.add(new Object[]{Sniffer.No, arp.sender_hardaddr, arp.sender_protoaddr, arp.target_hardaddr, arp.target_protoaddr, "ARP",
                    arp.hardtype, arp.prototype, arp.hlen, arp.plen, arp.operation, arp.data});

            DefaultTableModel model = (DefaultTableModel) Sniffer.jTable1.getModel();
            model.addRow(row);
            Sniffer.No++;

        } else if (packet instanceof IPPacket) {

            ip = (IPPacket) packet;

            Object[] row = {Sniffer.No, ip.length, ip.src_ip, ip.dst_ip, "IP"};
            rowList.add(new Object[]{Sniffer.No, ip.length, ip.src_ip, ip.dst_ip, "IP", ip.version,
                    ip.priority, ip.d_flag, ip.t_flag, ip.r_flag, ip.rsv_tos,
                    ip.rsv_frag, ip.dont_frag, ip.more_frag, ip.offset, ip.hop_limit,
                    ip.protocol, ip.ident, ip.flow_label, ip.option, ip.data});

            DefaultTableModel model = (DefaultTableModel) Sniffer.jTable1.getModel();
            model.addRow(row);
            Sniffer.No++;

        }

    }
}
