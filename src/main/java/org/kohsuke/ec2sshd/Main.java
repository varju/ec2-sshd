package org.kohsuke.ec2sshd;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Logger;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKeyFactory;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

/**
 * SSH server to be run on EC2 Windows instance to accept connections from clients.
 *
 * @author Kohsuke Kawaguchi
 */
public class Main {
    @Option(name="-p",usage="Listen on this TCP port. Defaults to 22")
    public int port = 22;

    @Option(name="-key",usage="Use the given public key for authentication, instead of instance metadata from EC2")
    public File keyFile;

    public static void main(String[] args) throws Exception {
        Main main = new Main();
        CmdLineParser parser = new CmdLineParser(main);
        try {
            parser.parseArgument(args);
            main.run();
        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            parser.printUsage(System.err);
            System.exit(1);
        }
    }

    public  void run() throws Exception {
        SecurityUtils.setRegisterBouncyCastle(true); // really make sure we have Bouncy Castle, or else die.

        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPublicKeyFactory()));
        sshd.setCipherFactories(Arrays.asList(// AES 256 and 192 requires unlimited crypto, so don't use that
                (NamedFactory<Cipher>) BuiltinCiphers.aes128cbc,
                BuiltinCiphers.tripledescbc,
                BuiltinCiphers.blowfishcbc));

        sshd.setPort(port);

        // TODO: perhaps we can compute the digest of the userdata and somehow turn it into the key?
        // for the Hudson master to be able to authenticate the EC2 instance (in the face of man-in-the-middle attack possibility),
        // we need the server to know some secret.
        sshd.setKeyPairProvider(new KeyPairProviderImpl());     // for now, Hudson doesn't authenticate the EC2 instance.

        sshd.setShellFactory(new ProcessShellFactory(new String[] {"cmd.exe"}));
        sshd.setCommandFactory(new ScpCommandFactory.Builder().withDelegate(new CommandFactoryImpl()).build());

        // load key from command line argument for debug assistance
        KeyProvider kp = keyFile == null ? new EC2InstanceDataKeyProvider() : new FileKeyProvider(keyFile);
        final PublicKey master = kp.getKey();

        // the client needs to possess the private key used for launching EC2 instance.
        // this enables us to authenticate the legitimate user.
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String s, PublicKey publicKey, ServerSession serverSession) {
                return publicKey.equals(master);
            }
        });

        sshd.start();
    }

    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

}
