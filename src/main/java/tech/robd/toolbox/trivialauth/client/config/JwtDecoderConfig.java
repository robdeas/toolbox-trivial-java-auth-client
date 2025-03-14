package tech.robd.toolbox.trivialauth.client.config;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import io.jsonwebtoken.io.Decoders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
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

    private static final Logger logger = LoggerFactory.getLogger(JwtDecoderConfig.class);
    private final SecretKey jwtSecret = loadSecretKeyFromFile();

    private SecretKey loadSecretKeyFromFile() {
        try {
            // Use the same path as in your JwtTokenUtil
            Path keyPath = Paths.get("config", "jwt-key.txt");
            logger.info("Loading JWT secret key from file: {}", keyPath.toAbsolutePath());

            var lines = Files.readAllLines(keyPath);
            var startIndex = !lines.isEmpty() && lines.getFirst().trim().startsWith("#") ? 1 : 0;

            var keyContent = lines.subList(startIndex, lines.size()).stream()
                    .map(line -> line.replaceAll("\\s+", ""))
                    .collect(Collectors.joining());
            byte[] decodedKey = Decoders.BASE64.decode(keyContent);
            logger.debug("JWT secret key loaded successfully");
            // Compute SHA-256 hash of key
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = digest.digest(decodedKey);
                String hexHash = HexFormat.of().formatHex(hashBytes);
                logger.debug("JWT secret key loaded successfully, SHA-256 hash: {}", hexHash);
            } catch (NoSuchAlgorithmException ex) {
                logger.warn("SHA-256 algorithm not available, skipping hash logging", ex);
            }
            return new SecretKeySpec(decodedKey, SignatureAlgorithm.HS512.getJcaName());
        } catch (IOException e) {
            logger.error("Failed to load JWT secret key from file", e);
            throw new RuntimeException("Failed to load JWT secret key from file", e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        logger.info("Creating JwtDecoder bean using HMAC HS512 algorithm");
        return NimbusJwtDecoder.withSecretKey(getSecretKey())
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
    }

    private SecretKey getSecretKey() {
        return jwtSecret;
    }
}