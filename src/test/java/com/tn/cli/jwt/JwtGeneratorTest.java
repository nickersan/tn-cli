package com.tn.cli.jwt;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.PrintStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatcher;

import com.tn.cli.MissingOptionException;

class JwtGeneratorTest
{
  private static final KeyPair KEY_PAIR = keyPair();
  private static final String PRIVATE_KEY = Base64.getEncoder().encodeToString(KEY_PAIR.getPrivate().getEncoded());
  private static final String ID = "1";
  private static final String ISSUER = "test";
  private static final String SUBJECT = "sub";
  private static final Collection<String> SHORT_REQUIRED_OPTIONS = List.of("-k", "-t", "-r", "-s");
  private static final Map<String, String> SHORT_ARGS = Map.of("-i", ID, "-k", PRIVATE_KEY, "-t", "RSA", "-r", ISSUER, "-s", SUBJECT);
  private static final Collection<String> LONG_REQUIRED_OPTIONS = List.of("--key", "--key-type", "--issuer", "--subject");
  private static final Map<String, String> LONG_ARGS = Map.of("--id", ID, "--key", PRIVATE_KEY, "--key-type",  "RSA", "--issuer", ISSUER, "--subject", SUBJECT);

  @ParameterizedTest
  @MethodSource("args")
  void shouldGenerateJwt(String[] args) throws Exception
  {
    PrintStream out = mock(PrintStream.class);

    new JwtGenerator(out).run(args);

    verify(out).println(argThat(decodesToExpectedToken()));
  }

  @ParameterizedTest
  @MethodSource("args")
  void shouldGenerateJwtWithAudiences(String[] args) throws Exception
  {
    PrintStream out = mock(PrintStream.class);

    new JwtGenerator(out).run(Stream.concat(Stream.of(args), Stream.of("-a", "A1", "--audience", "A2")).toArray(String[]::new));

    verify(out).println(argThat(decodesToExpectedToken(Set.of("A1", "A2"))));
  }

  @ParameterizedTest
  @MethodSource("args")
  void shouldGenerateJwtWithClaims(String[] args) throws Exception
  {
    PrintStream out = mock(PrintStream.class);

    new JwtGenerator(out).run(Stream.concat(Stream.of(args), Stream.of("-c", "C1=A", "--claim", "C2 = B")).toArray(String[]::new));

    verify(out).println(argThat(decodesToExpectedToken(Map.of("C1", "A", "C2", "B"))));
  }

  private static Stream<Arguments> args()
  {
    return Stream.of(args(SHORT_ARGS), args(LONG_ARGS));
  }

  private static Arguments args(Map<String, String> args)
  {
    return arguments(
      (Object)args.entrySet().stream()
        .flatMap(entry -> Stream.of(entry.getKey(), entry.getValue()))
        .toArray(String[]::new)
    );
  }

  @ParameterizedTest
  @MethodSource("invalidArgs")
  void shouldFailWhenRequiredOptionsMissing(String[] args)
  {
    assertThrows(MissingOptionException.class, () -> new JwtGenerator(mock(PrintStream.class)).run(args));
  }

  private static Stream<Arguments> invalidArgs()
  {
    return Stream.concat(invalidArgs(SHORT_REQUIRED_OPTIONS, SHORT_ARGS), invalidArgs(LONG_REQUIRED_OPTIONS, LONG_ARGS));
  }

  private static Stream<Arguments> invalidArgs(Collection<String> requiredOptions, Map<String, String> args)
  {
    return requiredOptions.stream().map(
      requiredOption -> arguments(
        (Object)args.entrySet().stream()
          .filter(entry -> !entry.getKey().equals(requiredOption))
          .flatMap(entry -> Stream.of(entry.getKey(), entry.getValue()))
          .toArray(String[]::new)
      )
    );
  }

  private static ArgumentMatcher<String> decodesToExpectedToken()
  {
    return s -> decodesToExpectedToken(s, emptySet(), emptyMap());
  }

  private static ArgumentMatcher<String> decodesToExpectedToken(Collection<String> audiences)
  {
    return s -> decodesToExpectedToken(s, audiences, emptyMap());
  }

  private static ArgumentMatcher<String> decodesToExpectedToken(Map<String, Object> claims)
  {
    return s -> decodesToExpectedToken(s, emptySet(), claims);
  }

  private static boolean decodesToExpectedToken(String token, Collection<String> audience, Map<String, Object> claims)
  {
    Jwt<JwsHeader, Claims> jwt = Jwts.parser().verifyWith(KEY_PAIR.getPublic()).build().parseSignedClaims(token.trim());
    Claims payload = jwt.getPayload();

    return payload.getId().equals(ID)
      && payload.getIssuer().equals(ISSUER)
      && payload.getSubject().equals(SUBJECT)
      && (audience.isEmpty() || payload.getAudience().containsAll(audience))
      && (claims.isEmpty() || payload.entrySet().containsAll(claims.entrySet()));
  }

  private static KeyPair keyPair()
  {
    try
    {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);

      return keyPairGenerator.generateKeyPair();
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new IllegalStateException(e);
    }
  }
}
