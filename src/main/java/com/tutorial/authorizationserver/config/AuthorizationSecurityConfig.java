package com.tutorial.authorizationserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.tutorial.authorizationserver.service.ClientService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@RequiredArgsConstructor
@Slf4j
@EnableWebSecurity
public class AuthorizationSecurityConfig {
	
	private final PasswordEncoder passwordEncoder;
	private final ClientService clientService;
	
	@Bean
	@Order(1)
	SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

		http.exceptionHandling(
				(exception) -> exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
				// Accept access tokens for User Info and/or Client Registration
				.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
		// .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); //deprecated

		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/**", "/client/**").permitAll().anyRequest().authenticated()).formLogin(Customizer.withDefaults());
		
		//http.csrf().ignoringRequestMatchers("/auth/**", "/client/**"); //deprecated
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/auth/**", "/client/**"));

		return http.build();
	}

	/*
	 * @Bean UserDetailsService userDetailsService() { UserDetails userDetails =
	 * User.withUsername("user").password("{noop}user").authorities("ROLE_USER").
	 * build();
	 * 
	 * return new InMemoryUserDetailsManager(userDetails); }
	 */

	/*
	 * @Bean RegisteredClientRepository registeredClientRepository() {
	 * RegisteredClient registeredClient =
	 * RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client")
	 * //.clientSecret("{noop}secret")
	 * .clientSecret(passwordEncoder.encode("secret"))
	 * .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	 * .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	 * .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
	 * .redirectUri("https://oauthdebugger.com/debug") //
	 * .postLogoutRedirectUri("http://127.0.0.1:8080/") .scope(OidcScopes.OPENID) //
	 * .scope(OidcScopes.PROFILE) //
	 * .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).
	 * build()) .clientSettings(clientSettings()).build();
	 * 
	 * return new InMemoryRegisteredClientRepository(registeredClient); }
	 */
	
	/*
	 * @Bean ClientSettings clientSettings() { return
	 * ClientSettings.builder().requireProofKey(true).build(); }
	 */
	
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			Authentication principal = context.getPrincipal();
			
			if(context.getTokenType().getValue().equals("id_token")) {
				context.getClaims().claim("token_type", "id token");
			}
			
			if(context.getTokenType().getValue().equals("access_token")) {
				context.getClaims().claim("token_type", "access token");
				
				Set<String> roles = principal.getAuthorities()
											 .stream()
											 .map(GrantedAuthority::getAuthority)
											 .collect(Collectors.toSet());
				
				context.getClaims().claim("roles", roles).claim("username", principal.getName());
			}
		};
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRSAKey();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	private static RSAKey generateRSAKey() {
		KeyPair keyPair = generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	private static KeyPair generateKeyPair() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
		return keyPair;
	}
}
