package tech.robd.toolbox.trivialauth.client.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import tech.robd.toolbox.trivialauth.client.security.CustomAuthenticationProvider;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    private final JwtDecoder jwtDecoder;

    public WebSecurityConfig(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
        logger.info("WebSecurityConfig initialized with JwtDecoder: {}", jwtDecoder);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.info("Configuring security filter chain");
        http
                // Disable CSRF for simplicity (consider enabling for production with proper configuration)
                .csrf(AbstractHttpConfigurer::disable)

                // Configure authorization rules
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/css/**", "/js/**").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().authenticated()
                )

                // For REST endpoints, return a 401 Unauthorized instead of redirecting
                .exceptionHandling(exception -> exception
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new AntPathRequestMatcher("/api/**")
                        )
                )

                // Configure form login for the Thymeleaf-based pages
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .logout(LogoutConfigurer::permitAll)

                // Enable JWT for bearer token auth
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder))
                );

        SecurityFilterChain filterChain = http.build();
        logger.debug("Security filter chain configured successfully");
        return filterChain;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        logger.info("Creating AuthenticationManager bean");
        AuthenticationManager authManager = new ProviderManager(customAuthenticationProvider());
        logger.debug("AuthenticationManager created successfully");
        return authManager;
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider() {
        logger.info("Creating customAuthenticationProvider bean");
        return new CustomAuthenticationProvider();
    }
}