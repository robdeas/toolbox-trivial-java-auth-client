package tech.robd.toolbox.trivialauth.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import tech.robd.toolbox.trivialauth.client.security.CustomAuthenticationProvider;

@Configuration
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for simplicity (TODO Try to avoid this in production)
                .csrf(AbstractHttpConfigurer::disable)
                // Register custom authentication provider
                .authenticationProvider(new CustomAuthenticationProvider())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/css/**", "/js/**").permitAll() // public paths
                        .requestMatchers("/api/**").authenticated()                // REST endpoints require auth
                        .anyRequest().authenticated()                                // all other endpoints require auth
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
                .logout(LogoutConfigurer::permitAll);

        return http.build();
    }
}
