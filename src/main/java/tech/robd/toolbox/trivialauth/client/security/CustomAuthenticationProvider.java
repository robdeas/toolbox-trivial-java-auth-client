package tech.robd.toolbox.trivialauth.client.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.client.RestTemplate;

import java.util.*;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;



public class CustomAuthenticationProvider implements AuthenticationProvider {


   private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

   private final RestTemplate restTemplate = new RestTemplate();
   private final String authServiceUrl = "http://localhost:8081/authenticate";

   @Override
   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
      String username = authentication.getName();
      String password = authentication.getCredentials().toString();

      logger.info("Attempting authentication for user: {}", username);

      // Prepare request payload
      Map<String, String> requestBody = new HashMap<>();
      requestBody.put("username", username);
      requestBody.put("password", password);

      // Set headers
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);

      try {
         // Make the POST call to the authentication service
         logger.debug("Sending authentication request for user: {}", username);
         ResponseEntity<Map> response = restTemplate.postForEntity(authServiceUrl, request, Map.class);
         logger.debug("Received response with status: {}", response.getStatusCode());
         if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            // Get the JWT token
            String jwtToken = (String) response.getBody().get("token");
            if (jwtToken != null && !jwtToken.isEmpty()) {
               logger.info("User {} authenticated successfully.", username);
               // Extract user roles from token
               List<GrantedAuthority> authorities = extractAuthoritiesFromToken(jwtToken);

               // Create authenticated token with authorities
               return new UsernamePasswordAuthenticationToken(
                       username,
                       jwtToken,
                       authorities
               );
            }
         }
      } catch (Exception ex) {
         logger.error("Error occurred during authentication for user: {}", username, ex);
         throw new AuthenticationServiceException("Authentication service error", ex);
      }
      logger.warn("Authentication failed for user: {}", username);
      throw new BadCredentialsException("Authentication failed");
   }

   private List<GrantedAuthority> extractAuthoritiesFromToken(String jwtToken) {
      try {
         // Decode token parts (simple parsing for demo purposes)
         String[] chunks = jwtToken.split("\\.");
         if (chunks.length < 2) {
            logger.warn("Invalid JWT token structure for token: {}", jwtToken);
            return Collections.emptyList();
         }

         // Decode the payload
         Base64.Decoder decoder = Base64.getUrlDecoder();
         String payload = new String(decoder.decode(chunks[1]));

         // Parse JSON
         ObjectMapper mapper = new ObjectMapper();
         Map<String, Object> claims = mapper.readValue(payload, Map.class);

          // Extract role
         String role = (String) claims.get("role");
         if (role != null && !role.isEmpty()) {
            logger.debug("Extracted role {} from token for user.", role);
            // Prefix with ROLE_ as Spring Security convention
            return List.of(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
         }
         logger.warn("No role found in token.");
         return Collections.emptyList();
      } catch (Exception e) {
         // If token parsing fails, return empty authorities
         logger.error("Error extracting authorities from token", e);
         return Collections.emptyList();
      }
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
   }
}