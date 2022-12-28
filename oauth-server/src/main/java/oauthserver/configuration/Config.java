package oauthserver.configuration;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class Config {

    public static final String ISSUER_NAME = "OAuth Server";
    public static final String FLOW_ID_COOKIE = "flow_id";
    public static final Integer FLOW_ID_COOKIE_EXPIRE_TIME_SECONDS = 300;
    public static final Integer AUTH_CODE_LENGTH = 30;

    public static final Integer ACCESS_TOKEN_EXPIRE_TIME_SECONDS = 600;
    public static final Integer ID_TOKEN_EXPIRE_TIME_SECONDS = 600;

    @Value("${secret_key}")
    private String secretKey;

    public String getSecretKey() { return this.secretKey; }

    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        return new InMemoryUserDetailsManager();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                    .anyRequest().permitAll()
                .and().formLogin().disable();
        return http.build();

    }
    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Key jwtSecretSigningKey() {
        return Keys.hmacShaKeyFor(this.secretKey.getBytes(StandardCharsets.UTF_8));
    }

}
