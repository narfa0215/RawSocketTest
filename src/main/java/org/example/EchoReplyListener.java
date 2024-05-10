package org.example;

import org.savarese.vserv.tcpip.ICMPEchoPacket;

import java.io.IOException;

public interface EchoReplyListener {
    void notifyEchoReply(ICMPEchoPacket packet, byte[] data, int dataOffset, byte[] srcAddress) throws IOException;
}
