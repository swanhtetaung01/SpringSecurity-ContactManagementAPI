
package com.project.spring_security.contact_management.security;

import com.project.spring_security.contact_management.security.jwt.AuthEntryPointJwt;
import com.project.spring_security.contact_management.security.jwt.AuthTokenFilter;
import jakarta.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeaderSecurityNavigator;
import org.springframework.security.config.annotation.web.configurers.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthEntryPointJwt unAuthorizedHandler;

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http.securityConfigurer(builder -> builder
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/signin").permitAll()
                        .requestMatchers("/contacts/public/info").permitAll()
                        .requestMatchers(HttpMethod.POST, "/contacts").hasRole("ADMIN")
//                        .requestMatchers(HttpMethod.GET, "/contacts").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/contacts/{id}").hasRole("ADMIN")
                        .anyRequest()).and().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .headers(HeadersConfigurer::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unAuthorizedHandler));
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    @Bean
    public MarkerUserDetailService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initialData(UserDetailService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;

            if (!manager.userExists("adminUser1")) {
                UserDetails adminUser = User.withUsername("adminUser1")
                        .password(passwordEncoder().encode("admin1password"))
                        .roles("ADMIN")
                        .build();
                manager.createUser(adminUser);
            }

            if (!manager.userExists("regularUser1")) {
                UserDetails regularUser = User.withUsername("regularUser1")
                        .password(passwordEncoder().encode("regular1password"))
                        .roles("USER")
                        .build();
                manager.createUser(regularUser);
            }
        };
    }
}