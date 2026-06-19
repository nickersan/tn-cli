package com.tn.cli.jwt;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toMap;

import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import jakarta.annotation.Nonnull;

import io.jsonwebtoken.Jwts;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.help.HelpFormatter;
import org.apache.commons.cli.help.TextHelpAppendable;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.tn.cli.MissingOptionException;

@SpringBootApplication
public class JwtGenerator implements CommandLineRunner
{
  private static final int CLAIM_NAME = 0;
  private static final int CLAIM_VALUE = 1;
  private static final String CLAIM_SEPARATOR = "=";
  private static final long DEFAULT_TTL = TimeUnit.MINUTES.toMillis(30);
  private static final Option OPTION_AUDIENCE = new Option("a", "audience", true, "an audience");
  private static final Option OPTION_CLAIM = new Option("c", "claim", true, "a claim in name=value format");
  private static final Option OPTION_HELP = new Option("h", "help", false, "prints the help");
  private static final Option OPTION_ID = new Option("i", "id", true, "the id");
  private static final Option OPTION_ISSUER = new Option("r", "issuer", true, "the issuer");
  private static final Option OPTION_SUBJECT = new Option("s", "subject", true, "the subject");
  private static final Option OPTION_TTL = new Option("ttl", "time-to-live", true, "the time-to-live in minutes; defaults to 30 minutes");
  private static final Option OPTION_SIGNING_ALGORITHM = new Option("t", "key-type", true, "the algorithm used to generate the key");
  private static final Option OPTION_SIGNING_KEY = new Option("k", "key", true, "the key");

  private static final Options OPTIONS = new Options()
    .addOption(OPTION_AUDIENCE)
    .addOption(OPTION_CLAIM)
    .addOption(OPTION_HELP)
    .addOption(OPTION_ID)
    .addOption(OPTION_ISSUER)
    .addOption(OPTION_SUBJECT)
    .addOption(OPTION_TTL)
    .addOption(OPTION_SIGNING_ALGORITHM)
    .addOption(OPTION_SIGNING_KEY);

  private final PrintStream out;

  static void main(String[] args)
  {
    SpringApplication.run(JwtGenerator.class, args);
  }

  public JwtGenerator()
  {
    this(System.out);
  }

  public JwtGenerator(PrintStream out)
  {
    this.out = out;
  }

  @Override
  public void run(@Nonnull String... args) throws Exception
  {
    CommandLineParser commandLineParser = new DefaultParser();
    CommandLine commandLine = commandLineParser.parse(OPTIONS, args);

    if (commandLine.hasOption(OPTION_HELP)) printHelp();
    else jwt(commandLine);
  }

  private void jwt(CommandLine commandLine) throws NoSuchAlgorithmException, InvalidKeySpecException
  {
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(optionValue(commandLine, OPTION_SIGNING_KEY)));
    PrivateKey key = KeyFactory.getInstance(optionValue(commandLine, OPTION_SIGNING_ALGORITHM)).generatePrivate(keySpec);

    out.println(
      "\n"
      + Jwts.builder()
        .id(id(commandLine))
        .issuer(optionValue(commandLine, OPTION_ISSUER))
        .subject(optionValue(commandLine, OPTION_SUBJECT))
        .audience().add(audience(commandLine)).and()
        .claims(claims(commandLine))
        .issuedAt(new Date())
        .expiration(expiration(commandLine))
        .signWith(key)
        .compact()
      + "\n"
    );
  }

  private Collection<String> audience(CommandLine commandLine)
  {
    return commandLine.hasOption(OPTION_AUDIENCE)
      ? Set.of(commandLine.getOptionValues(OPTION_AUDIENCE))
      : emptySet();
  }

  private Map<String, String> claims(CommandLine commandLine)
  {
    if (!commandLine.hasOption(OPTION_CLAIM)) return emptyMap();

    return Stream.of(commandLine.getOptionValues(OPTION_CLAIM))
      .map(JwtGenerator::claimTokens)
      .collect(toMap(claimTokens -> claimTokens[CLAIM_NAME].trim(), claimTokens -> claimTokens[CLAIM_VALUE].trim()));
  }

  private static String[] claimTokens(String claim)
  {
    String[] claimTokens = claim.split(CLAIM_SEPARATOR);
    if (claimTokens.length != 2) throw new IllegalClaimException("Illegal claim: " + claim);

    return claimTokens;
  }

  private Date expiration(CommandLine commandLine)
  {
    return new Date(
      System.currentTimeMillis()
        + (commandLine.hasOption(OPTION_TTL) ? Long.parseLong(commandLine.getOptionValue(OPTION_TTL)) : DEFAULT_TTL)
    );
  }

  private String id(CommandLine commandLine)
  {
    return commandLine.getOptionValue(OPTION_ID, Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes()));
  }

  private String optionValue(CommandLine commandLine, Option option)
  {
    checkOption(commandLine, option);

    return commandLine.getOptionValue(option);
  }

  private void checkOption(CommandLine commandLine, Option option)
  {
    if (!commandLine.hasOption(option)) throw new MissingOptionException("Missing option: " + option);
  }

  private void printHelp()
  {
    try
    {
      HelpFormatter.builder()
        .setHelpAppendable(new TextHelpAppendable(out))
        .get()
        .printOptions(OPTIONS);
    }
    catch (IOException e)
    {
      e.printStackTrace(out);
    }
  }
}
