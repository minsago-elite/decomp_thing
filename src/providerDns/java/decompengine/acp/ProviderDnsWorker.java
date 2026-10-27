package decompengine.acp;

import java.io.DataOutputStream;
import java.net.InetAddress;

/** A credential-free process boundary, not an application or configurable DNS client. */
public final class ProviderDnsWorker {
    private ProviderDnsWorker() { }

    public static void main(String[] args) {
        if (args.length != 0) System.exit(2);
        try {
            InetAddress[] resolved = InetAddress.getAllByName("chatgpt.com");
            if (resolved.length == 0) System.exit(2);
            byte[] address = resolved[0].getAddress();
            if (address.length != 4 && address.length != 16) System.exit(2);
            DataOutputStream output = new DataOutputStream(System.out);
            output.writeInt(0x41445031); // ADP1: exactly one selected numeric address.
            output.writeByte(address.length == 4 ? 4 : 6);
            output.write(address);
            output.flush();
        } catch (Throwable ignored) {
            // No exception, resolver response, address or runtime path crosses this boundary.
            System.exit(2);
        }
    }
}
