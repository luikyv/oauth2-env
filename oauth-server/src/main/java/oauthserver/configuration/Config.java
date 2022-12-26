package oauthserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Config {
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
}
