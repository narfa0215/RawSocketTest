package org.example;

import org.savarese.vserv.tcpip.ICMPEchoPacket;
import org.savarese.vserv.tcpip.OctetConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        final String localhost = "localhost";
        final int pingCount = 5;

        final ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(2);

        try {
            final InetAddress address = InetAddress.getByName(localhost);
            final String hostname = address.getCanonicalHostName();
            final String hostaddr = address.getHostAddress();

            // Ping programs usually use the process ID for the identifier,
            // but we can't get it and this is only a demo.
            final int id = 65535;
            final Pinger ping;

            if (address instanceof Inet6Address) {
                ping = new PingerIPv6(id);
            } else {
                ping = new Pinger(id);
            }

            ping.setEchoReplyListener(new EchoReplyListener() {
                StringBuffer buffer = new StringBuffer(128);

                public void notifyEchoReply(final ICMPEchoPacket packet, final byte[] data, final int dataOffset, final byte[] srcAddress) throws IOException {
                    final long end = System.nanoTime();
                    final long start = OctetConverter.octetsToLong(data, dataOffset);
                    // Note: Java and JNI overhead will be noticeable (100-200
                    // microseconds) for sub-millisecond transmission times.
                    // The first ping may even show several seconds of delay
                    // because of initial JIT compilation overhead.
                    final double rtt = (double) (end - start) / 1e6;

                    buffer.setLength(0);
                    buffer.append(packet.getICMPPacketByteLength()).append(" bytes from ").append(hostname).append(" (");
                    buffer.append(InetAddress.getByAddress(srcAddress).toString());
                    buffer.append("): icmp_seq=").append(packet.getSequenceNumber()).append(" ttl=").append(packet.getTTL()).append(" time=").append(rtt).append(" ms");
                    log.info(buffer.toString());
                }
            });

            log.info("PING {} ({}) {} ({}) bytes of data).", hostname, hostaddr, ping.getRequestDataLength(), ping.getRequestPacketLength());

            final CountDownLatch latch = new CountDownLatch(1);

            executor.scheduleAtFixedRate(new Runnable() {
                int counter = pingCount;

                public void run() {
                    try {
                        if (counter > 0) {
                            ping.sendEchoRequest(address);
                            if (counter == pingCount) {
                                latch.countDown();
                            }
                            --counter;
                        } else {
                            executor.shutdown();
                        }
                    } catch (final IOException ioe) {
                        ioe.printStackTrace();
                    }
                }
            }, 0, 1, TimeUnit.SECONDS);

            // We wait for first ping to be sent because Windows times out
            // with WSAETIMEDOUT if echo request hasn't been sent first.
            // POSIX does the right thing and just blocks on the first receive.
            // An alternative is to bind the socket first, which should allow a
            // receive to be performed first on Windows.
            latch.await();

            for (int i = 0; i < pingCount; ++i) {
                ping.receiveEchoReply();
            }

            ping.close();
        } catch (final Exception e) {
            executor.shutdown();
            e.printStackTrace();
        }
    }
}