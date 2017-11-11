package org.kondrak.pcap;

import java.util.Comparator;
import java.util.function.Function;
import java.util.function.ToDoubleFunction;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;

public class HostAddressStatDescending implements Comparator<HostAddressStat> {

    @Override
    public int compare(HostAddressStat o1, HostAddressStat o2) {
        return o1.getCount() - o2.getCount();
    }

    @Override
    public Comparator<HostAddressStat> reversed() {
        return new Comparator<HostAddressStat>() {
            @Override
            public int compare(HostAddressStat o1, HostAddressStat o2) {
                return o2.getCount() - o1.getCount();
            }
        };
    }

    @Override
    public Comparator<HostAddressStat> thenComparing(Comparator<? super HostAddressStat> other) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <U> Comparator<HostAddressStat> thenComparing(Function<? super HostAddressStat, ? extends U> keyExtractor, Comparator<? super U> keyComparator) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <U extends Comparable<? super U>> Comparator<HostAddressStat> thenComparing(Function<? super HostAddressStat, ? extends U> keyExtractor) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Comparator<HostAddressStat> thenComparingInt(ToIntFunction<? super HostAddressStat> keyExtractor) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Comparator<HostAddressStat> thenComparingLong(ToLongFunction<? super HostAddressStat> keyExtractor) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Comparator<HostAddressStat> thenComparingDouble(ToDoubleFunction<? super HostAddressStat> keyExtractor) {
        throw new UnsupportedOperationException();
    }
}
