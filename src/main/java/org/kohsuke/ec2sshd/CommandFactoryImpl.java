package org.kohsuke.ec2sshd;

import java.util.logging.Logger;
import java.util.Arrays;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;

/**
 * {@link CommandFactory} that uses {@link Process}
 *
 * @author Kohsuke Kawaguchi
*/
class CommandFactoryImpl implements CommandFactory {
    public Command createCommand(String command) {
        LOGGER.info("Forking "+command);
        // TODO: proper quote handling
        return new CommandImpl(new ProcessBuilder(Arrays.asList("bash", "-c", command)));
    }

    private static final Logger LOGGER = Logger.getLogger(CommandFactoryImpl.class.getName());
}
