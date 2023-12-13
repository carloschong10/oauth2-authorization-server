package com.tutorial.authorizationserver.entity;

import java.util.Date;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "client")
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class Client {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	
	private String clientId;
	private String clientSecret;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<ClientAuthenticationMethod> authenticationMethods;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<AuthorizationGrantType> authorizationGrantTypes;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<String> redirectUris;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<String> scopes;
	
	private boolean requireProofKey;
	
	public static RegisteredClient toRegisteredClient(Client client) {
		RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
				.clientId(client.getClientId())
				.clientSecret(client.getClientSecret())
				.clientIdIssuedAt(new Date().toInstant())
				.clientAuthenticationMethods(am -> am.addAll(client.getAuthenticationMethods()))
				.authorizationGrantTypes(agt -> agt.addAll(client.getAuthorizationGrantTypes()))
				.redirectUris(ru -> ru.addAll(client.getRedirectUris()))
				.scopes(sc -> sc.addAll(client.getScopes()))
				.clientSettings(ClientSettings
						.builder()
						.requireProofKey(client.isRequireProofKey())
						.build());
		
		return builder.build();
	}
}
