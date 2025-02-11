package com.jldevs.jwt.config;

import com.jldevs.jwt.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	@Autowired
	private JwtAuthenticationFilter jwtAuthFilter;

	@Autowired
	private UserDetailsService userDetailsService;

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/api/auth/registro").permitAll()  // Permitir registro
						.requestMatchers("/api/auth/usuarios").permitAll()
						.requestMatchers("/api/auth/login").permitAll()     // Permitir login
						.requestMatchers("/h2-console/**").permitAll()      // Permitir H2 Console
						.requestMatchers("/api/secured/**").authenticated()  // Explicitly configure secured endpoints
						.requestMatchers("/api/secured/admin/**").hasRole("ADMIN")
						.requestMatchers("/api/secured/user/**").hasRole("USER")
						.anyRequest().authenticated()
				)
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				)
				.authenticationProvider(authenticationProvider())
				.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

		// Para H2 Console
		http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
		// Add this for debugging
		http.httpBasic(Customizer.withDefaults());

		return http.build();
	}


	@Bean
	public AuthenticationManager authenticationManager(
			AuthenticationConfiguration configuration
	) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}