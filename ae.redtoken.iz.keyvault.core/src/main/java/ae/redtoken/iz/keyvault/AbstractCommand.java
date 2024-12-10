package ae.redtoken.iz.keyvault;

import org.apache.commons.cli.*;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Collectors;

public abstract class AbstractCommand {

    public AbstractCommand() {
        options.addOption(Option.builder().longOpt("help").option("h").desc("print help for this module").build());

        getAllCommandOptionAnnotatedFieldsFromClass(this.getClass()).forEach(field -> {
            System.out.println(field.getName());
            Option.Builder builder = Option.builder();
            CommandOption annotation = field.getAnnotation(CommandOption.class);

            if (annotation.description() != null)
                builder.desc(annotation.description());

            if (annotation.option() != null)
                builder.option(annotation.option());

            if (annotation.longOption() != null)
                builder.longOpt(annotation.longOption());

            builder.type(field.getType());
            builder.hasArg(!(field.getType().equals(boolean.class) || field.getType().equals(Boolean.class)));

            this.options.addOption(builder.build());
        });
    }

    interface SetCall {
        Object getValueFromString(String str) throws Exception;
    }
    static final Map<Class<?>, SetCall> vf = new HashMap<>();
    static {
        vf.put(String.class,(str) -> str);
        vf.put(int.class, Integer::parseInt);
        vf.put(double.class, Double::parseDouble);
    }


    protected Options options = new Options();

    Collection<Field> getAllCommandOptionAnnotatedFieldsFromClass(Class<?> cls) {
        Collection<Field> fields = new ArrayList<>();

        if (cls.getSuperclass() != null) {
            fields.addAll(getAllCommandOptionAnnotatedFieldsFromClass(cls.getSuperclass()));
        }

        fields.addAll(Arrays.stream(cls.getDeclaredFields())
                .filter(field -> field.getAnnotation(CommandOption.class) != null).collect(Collectors.toList()));
        return fields;
    }

    public void setUpAndExecute(List<String> args) {
        try {
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args.toArray(new String[0]));

            if (cmd.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp(this.getClass().getAnnotation(CommandModule.class).name(), options);
                return;
            }

            getAllCommandOptionAnnotatedFieldsFromClass(this.getClass()).forEach(field -> {
                try {
                    CommandOption annotation = field.getAnnotation(CommandOption.class);

                    String option = !annotation.option().equals("") ? annotation.option() : annotation.longOption();

                    if (field.getType().equals(boolean.class) || field.getType().equals(Boolean.class)) {
                        field.set(this, cmd.hasOption(option));
                        return;
                    }

                    if (!cmd.hasOption(option)) return;

                    System.out.println(cmd.getOptionValue(option));
                    System.out.println(cmd.getParsedOptionValue(option));

//                    field.set(this, vf.get(field.getType()).getValueFromString(cmd.getOptionValue(option)));
                    field.set(this, cmd.getParsedOptionValue(option));


                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            List<String> argList = cmd.getArgList();
            init();
            callCommand(argList);

        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    protected void callCommand(List<String> args) {
        String cmd = args.remove(0);

        try {
            Method method = this.getClass().getDeclaredMethod(cmd, List.class);
            method.invoke(this, args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void init() {
    }

    protected void help(List<String> args) {
        System.out.println("Help I need somebody, Help not just anybody!");
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    public @interface CommandModule {
        String name() default "";
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    public @interface CommandOption {
        String longOption();

        String description();

        String option() default "";
    }

    public static void execute(Class<?>[] commandModules, final List<String> args) {
        final String cm = args.remove(0);
        Arrays.stream(commandModules)
                .filter(AbstractCommand.class::isAssignableFrom)
                .filter(cls -> cls.getAnnotation(CommandModule.class) != null && cls.getAnnotation(CommandModule.class).name().equals(cm))
                .findFirst()
                .ifPresentOrElse(cls -> {
                    try {
                        Constructor<?> constructor = cls.getDeclaredConstructor();
                        AbstractCommand commandModule = (AbstractCommand) constructor.newInstance();
                        commandModule.setUpAndExecute(args);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, () -> {
                    //TODO: rec print help for all the available modules
                    throw new RuntimeException("No module");
                });
    }

}
