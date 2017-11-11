package org.kondrak.pcap;

import org.apache.commons.net.whois.WhoisClient;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private static final int MAX_TIMEOUTS = 10;
    private static final int MAX_PACKETS = 10000;

    public static void main(String[] args) {
        PcapHandle handle = null;
        List<HostAddressStat> ipAddrs = new ArrayList<>();

        try {
            InetAddress addr = InetAddress.getByName("192.168.42.4");
            PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 0);

            int timeoutCount = 0;
            int packetCount = 0;

            while(handle.isOpen() && packetCount < MAX_PACKETS) {
                try {
                    Packet packet = handle.getNextPacketEx();

                    IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                    if (ipPacket != null && ipPacket.getHeader() != null) {
                        Inet4Address srcAddr = ipPacket.getHeader().getSrcAddr();

                        if (!srcAddr.isAnyLocalAddress() && !srcAddr.toString().equalsIgnoreCase(addr.toString())) {

                            if (!contains(ipAddrs, srcAddr.toString())) {
                                HostAddressStat s = new HostAddressStat("Packet Count", srcAddr.toString(), srcAddr.getCanonicalHostName());
                                ipAddrs.add(s);
                                s.increment();
                            } else {
                                HostAddressStat st = getStatByAddress(ipAddrs, srcAddr.toString());
                                st.increment();
                            }

                            packetCount++;
                        }
                    } else {
                        LOG.debug("Encountered a non-ipv4 packet!");
                    }
                } catch(TimeoutException ex) {
                    LOG.debug("TIMEOUT: ", ex);
                    timeoutCount++;
                }

                if(timeoutCount > MAX_TIMEOUTS) {
                    handle.close();
                }
            }

            handle.close();
            LOG.debug("*** Normal exit! ***");

            LOG.debug("Source list:");

            Collections.sort(ipAddrs, new HostAddressStatDescending().reversed());
            WhoisClient client = new WhoisClient();
            for(HostAddressStat stat : ipAddrs) {
                LOG.debug("{} : {} - {}", stat.getHostAddr(), stat.getCount(), stat.getHostName());
                try {
                    client.connect(WhoisClient.DEFAULT_HOST);
                    String whois = client.query(stat.getFormattedHostAddr());

                    if(whois.startsWith("No match")) whois = "";

                    LOG.debug(whois);
                } catch(IOException ex) {
                    LOG.error("SHIT'S FUKT!");
                }
            }

            System.exit(0);

        } catch(UnknownHostException
                | EOFException
                | NotOpenException
                | PcapNativeException ex) {
            LOG.error("Exit due to error: ", ex);
            handle.close();
            System.exit(0);
        }
    }

    private static boolean contains(List<HostAddressStat> stats, String value) {
        boolean listContains = false;
//                            String logName = srcAddr.toString() + " " + srcAddr.getCanonicalHostName();
        for (HostAddressStat s : stats) {
            if (s.getHostAddr().equalsIgnoreCase(value)) {
                listContains = true;
                break;
            }
        }
        return listContains;
    }

    private static HostAddressStat getStatByAddress(List<HostAddressStat> stats, String value) {
        for (HostAddressStat s : stats) {
            if (s.getHostAddr().equalsIgnoreCase(value)) {
                return s;
            }
        }

        return null;
    }
}
