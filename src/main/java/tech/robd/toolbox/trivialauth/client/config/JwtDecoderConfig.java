package tech.robd.toolbox.trivialauth.client.config;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import io.jsonwebtoken.io.Decoders;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;

/**
 * Configuration class that provides the {@link JwtDecoder} bean for decoding JSON Web Tokens (JWTs).
 * The decoder is configured to use a symmetric key (HMAC) for validating tokens.
 *
 * The {@link JwtDecoder} returned by this configuration is essential for verifying the integrity and
 * authenticity of incoming JWTs in the application.
 *
 * This configuration is required when you want to use JWT bearer tokens to authenticate REST APIs directly.
 */
@Configuration
public class JwtDecoderConfig {


    private final SecretKey jwtSecret = loadSecretKeyFromFile();

    private SecretKey loadSecretKeyFromFile() {
        try {
            // Use the same path as in your JwtTokenUtil
            Path keyPath = Paths.get("config", "jwt-key.txt");

            var lines = Files.readAllLines(keyPath);
            var startIndex = !lines.isEmpty() && lines.getFirst().trim().startsWith("#") ? 1 : 0;

            var keyContent = lines.subList(startIndex, lines.size()).stream()
                    .map(line -> line.replaceAll("\\s+", ""))
                    .collect(Collectors.joining());
            byte[] decodedKey = Decoders.BASE64.decode(keyContent);
            return new SecretKeySpec(decodedKey, SignatureAlgorithm.HS512.getJcaName());
        } catch (IOException e) {
            throw new RuntimeException("Failed to load JWT secret key from file", e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(getSecretKey())
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
    }

    private SecretKey getSecretKey() {
        return jwtSecret;
    }
}