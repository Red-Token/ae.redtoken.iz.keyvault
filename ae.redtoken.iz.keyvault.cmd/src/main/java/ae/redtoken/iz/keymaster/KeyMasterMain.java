package ae.redtoken.iz.keymaster;

import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "iz-keymaster", mixinStandardHelpOptions = true, version = "v 0.0.1",
        description = "Keeper of keys",
        subcommands = {
        })

public class KeyMasterMain implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
        return 0;
    }

    public static int call(String[] args) {
        return new CommandLine(new KeyMasterMain()).setTrimQuotes(true).execute(args);
    }

    public static void main(String[] args) {
        System.exit(call(args));
    }
}
