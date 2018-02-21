package com.test;

import java.io.IOException;

import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws ExceptionReadingPcapFiles, IOException
    {
        //System.out.println( "Hello World!" );
        PcapFile pf = new PcapFile("C:\temp\temp2.pcap");
        pf.readOfflineFiles();
        /*final Tcp tcp = new Tcp();  
        
         
         * Same thing for our http header 
           
        final Http http = new Http();  
        
        final Pcap pcap = Pcap.openStream("C:\\temp\\temp2.pcap");
        
        pcap.loop(new PacketHandler() {
            public boolean nextPacket(Packet packet) throws IOException {
            	
                if (packet.hasProtocol(Protocol.TCP)) {

                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    String buffer = tcpPacket.getDestinationIP();
                   // if (buffer != null) {
                        System.out.println("TCP: " + tcp.getDescription());
                    //}
                } else if (packet.hasProtocol(Protocol.UDP)) {

                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                    Buffer buffer = udpPacket.getPayload();
                    if (buffer != null) {
                        System.out.println("UDP: " + buffer);
                    }
                }
                return true;
            }
        });*/
    }
   }

