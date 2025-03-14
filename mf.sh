#!/bin/bash

# Create necessary directories for tests
mkdir -p src/test/java/tech/robd/toolbox/trivialauth/client/controller
mkdir -p src/test/java/tech/robd/toolbox/trivialauth/client/config
mkdir -p src/test/java/tech/robd/toolbox/trivialauth/client/security

# Create ApiControllerTest.java
cat << 'EOF' > src/test/java/tech/robd/toolbox/trivialauth/client/controller/ApiControllerTest.java
package tech.robd.toolbox.trivialauth.client.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ApiController.class)
public class ApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser // Simulates an authenticated user
    public void testGetGreeting() throws Exception {
        mockMvc.perform(get("/api/greeting"))
               .andExpect(status().isOk())
               .andExpect(content().string("Hello from our secured REST endpoint!"));
    }
}
EOF

# Create DashboardControllerTest.java
cat << 'EOF' > src/test/java/tech/robd/toolbox/trivialauth/client/controller/DashboardControllerTest.java
package tech.robd.toolbox.trivialauth.client.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DashboardController.class)
public class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testDashboard() throws Exception {
        mockMvc.perform(get("/dashboard"))
               .andExpect(status().isOk())
               .andExpect(model().attribute("message", "Welcome to the dashboard!"))
               .andExpect(view().name("dashboard"));
    }
}
EOF

# Create LoginControllerTest.java
cat << 'EOF' > src/test/java/tech/robd/toolbox/trivialauth/client/controller/LoginControllerTest.java
package tech.robd.toolbox.trivialauth.client.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(LoginController.class)
public class LoginControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
               .andExpect(status().isOk())
               .andExpect(view().name("login"));
    }
}
EOF

# Create WebSecurityConfigTest.java
cat << 'EOF' > src/test/java/tech/robd/toolbox/trivialauth/client/config/WebSecurityConfigTest.java
package tech.robd.toolbox.trivialauth.client.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.SecurityFilterChain;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class WebSecurityConfigTest {

    @Autowired
    private SecurityFilterChain securityFilterChain;

    @Test
    public void testSecurityFilterChainBeanExists() {
        assertNotNull(securityFilterChain, "SecurityFilterChain bean should be available in the application context");
    }
}
EOF

# Create JwtDecoderConfigTest.java
cat << 'EOF' > src/test/java/tech/robd/toolbox/trivialauth/client/config/JwtDecoderConfigTest.java
package tech.robd.toolbox.trivialauth.client.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class JwtDecoderConfigTest {

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    public void testJwtDecoderBeanExists() {
        assertNotNull(jwtDecoder, "JwtDecoder bean should be created and available in the application context");
    }
}
EOF

# Create CustomAuthenticationProviderTest.java
cat << 'EOF' > src/test/java/tech/robd/toolbox/trivialauth/client/security/CustomAuthenticationProviderTest.java
package tech.robd.toolbox.trivialauth.client.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import static org.junit.jupiter.api.Assertions.*;

public class CustomAuthenticationProviderTest {

    private final CustomAuthenticationProvider provider = new CustomAuthenticationProvider();

    @Test
    public void testAuthenticateWithInvalidCredentials() {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken("user", "wrongPassword");
        // This test expects a BadCredentialsException. In a real test, you might need to mock the HTTP call.
        assertThrows(BadCredentialsException.class, () -> provider.authenticate(authToken));
    }
}
EOF

echo "Test files created successfully."
