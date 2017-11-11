package org.kondrak.pcap;

public class HostAddressStat {
    private final String statName;
    private final String hostAddr;
    private final String hostName;
    private int count;

    public HostAddressStat(String statName, String hostAddr, String hostName) {
        this.statName = statName;
        this.hostAddr = hostAddr;
        this.hostName = hostName;
    }

    public String getStatName() {
        return statName;
    }

    public String getHostAddr() {
        return hostAddr;
    }

    public String getHostName() {
        return hostName;
    }

    public String getFormattedHostAddr() {
        return hostAddr.replace("/", "");
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public void increment() {
        count++;
    }
}
