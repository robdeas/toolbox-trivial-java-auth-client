package tech.robd.toolbox.trivialauth.client.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;



public class CustomAuthenticationProvider implements AuthenticationProvider {

   private final RestTemplate restTemplate = new RestTemplate();
   private final String authServiceUrl = "http://localhost:8081/authenticate";


   @Override
   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
      String username = authentication.getName();
      String password = authentication.getCredentials().toString();

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
         ResponseEntity<Map> response = restTemplate.postForEntity(authServiceUrl, request, Map.class);
         if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            // Assume the JWT token is returned under the key "token"
            String jwtToken = (String) response.getBody().get("token");
            if (jwtToken != null && !jwtToken.isEmpty()) {
               // Authentication is successful; the token can be used as credentials or stored as needed.
               return new UsernamePasswordAuthenticationToken(username, jwtToken, Collections.emptyList());
            }
         }
      } catch (Exception ex) {
         // Optionally log the exception
         ex.printStackTrace();
      }

      // Return null if authentication failed
      return null;
   }


   // TODO If you wanted you could replace the authentication method with method below, to do quick and dirty local auth
   public Authentication authenticateLocally(Authentication authentication) throws AuthenticationException {
      String username = authentication.getName();
      String password = authentication.getCredentials().toString();
      
      // TODO Simulated authentication logic.
      if (password.equals(username + "-pass")) {
         return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());
      }

      return null; // authentication failed
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
   }
}
