package com.test;

import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.util.PcapPacketArrayList;

import io.pkts.packet.TCPPacket;

/**
 * @author Emad Heydari Beni Doing some IO functions related to PCAP files.
 */
public class PcapFile {

	/*************************************************
	 * Local Variables
	 *************************************************/
	String FileAddress = "C:\\temp\\temp2.pcap";

	/**
	 * 
	 * @param FileAddress
	 *            Address and the name of the PCAP file.
	 */
	public PcapFile(String FileAddress) {
		this.FileAddress = FileAddress;
	}

	/**
	 * Opens the offline Pcap-formatted file.
	 * 
	 * @throws ExceptionReadingPcapFiles
	 *             Facing any erro in opening the file
	 */
	public void readOfflineFiles() throws ExceptionReadingPcapFiles {
		// First, setup error buffer and name for our file
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs
		 final Tcp tcp = new Tcp();  
		 final Ip4 ip4 = new Ip4();
		
         final Http http = new Http();  

		// Second ,open up the selected file using openOffline call
		Pcap pcap = Pcap.openOffline("src\\main\\java\\wiresharkCapture.pcap", errbuf);

		// Throw exception if it cannot open the file
		if (pcap == null) {
			throw new ExceptionReadingPcapFiles(errbuf.toString());
		}

		// Next, we create a packet handler which will receive packets from the libpcap
		// loop.
		PcapPacketHandler<PcapPacketArrayList> jpacketHandler = new PcapPacketHandler<PcapPacketArrayList>() {
			byte[] sIP = new byte[4];
			public void nextPacket(PcapPacket packet, PcapPacketArrayList PaketsList) {
				if (!packet.hasHeader(tcp)) {
		            return; // not a TCP package, skip
		        }
		        if (!packet.hasHeader(http)) {
		            return; // not a HTTP package, skip
		        }
		        if (http.isResponse()) {
		            return; // not a HTTP request, skip
		        }
		        if (packet.hasHeader(ip4)) {
		        	
		        	sIP = packet.getHeader(ip4).source();
		        	}

		        
		       /* if (packet.hasHeader(tcp)) {
		        	System.out.println("Source IP: " + tcp.destination());
		        }
		       */
		        
		       // System.out.println("Referer: " + http.fieldValue(Request.Referer));
		       // System.out.println("Source IP: " + tcp);
		        String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
		        System.out.println("The source ip: " + sourceIP);
		        System.out.println("Request URL: " + http.fieldValue(Request.RequestUrl));
		      System.out.println("Host: " + http.fieldValue(Request.Host));

				PaketsList.add(packet);
			}
		};

		/***************************************************************************
		 * (From jNetPcap comments:) Fourth we enter the loop and tell it to capture
		 * unlimited packets. The loop method does a mapping of pcap.datalink() DLT
		 * value to JProtocol ID, which is needed by JScanner. The scanner scans the
		 * packet buffer and decodes the headers. The mapping is done automatically,
		 * although a variation on the loop method exists that allows the programmer to
		 * specify exactly which protocol ID to use as the data link type for this pcap
		 * interface.
		 **************************************************************************/

		try {
			PcapPacketArrayList packets = new PcapPacketArrayList();
			pcap.loop(-1, jpacketHandler, packets);
			
			/*//System.out.println("In here with packets as: " + );
			
			pcap.loop(10, new JPacketHandler<StringBuilder>() {  
				
	           
	  
	         
	            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
	  
	                
	                if (packet.hasHeader(Tcp.ID)) {  
	    
	                    packet.getHeader(tcp);  
	  
	                    System.out.printf("tcp.dst_port=%d%n", tcp.destination());  
	                    System.out.printf("tcp.src_port=%d%n", tcp.source());  
	                    System.out.printf("tcp.ack=%x%n", tcp.ack());  
	  
	                }  
	  
	            }      
	  
	        }); 
			*/
			
			
		} finally {
			// Last thing to do is close the pcap handle
			pcap.close();
		}

	
	}
}