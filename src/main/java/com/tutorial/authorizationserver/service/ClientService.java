package com.tutorial.authorizationserver.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import com.tutorial.authorizationserver.dto.ClientDto;
import com.tutorial.authorizationserver.dto.MessageDto;
import com.tutorial.authorizationserver.entity.Client;
import com.tutorial.authorizationserver.repository.ClientRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository{
	
	private final ClientRepository clientRepository;
	private final PasswordEncoder passwordEncoder;
	
	@Override
	public void save(RegisteredClient registeredClient) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public RegisteredClient findById(String id) {
		// TODO Auto-generated method stub
		Client client = clientRepository.findByClientId(id)
				.orElseThrow(()-> new RuntimeException("Cliente no encontrado"));
				
		return Client.toRegisteredClient(client);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		// TODO Auto-generated method stub
		Client client = clientRepository.findByClientId(clientId)
				.orElseThrow(()-> new RuntimeException("Cliente no encontrado"));
				
		return Client.toRegisteredClient(client);
	}
	
	public MessageDto create(ClientDto dto) {
		Client client = clientFromDto(dto);
		clientRepository.save(client);
		
		return new MessageDto("cliente: " + client.getClientId() + " guardado");
	}
	
	//private methods
	private Client clientFromDto(ClientDto dto) {
		Client client = Client.builder()
				.clientId(dto.getClientId())
				.clientSecret(passwordEncoder.encode(dto.getClientSecret()))
				.authenticationMethods(dto.getAuthenticationMethods())
				.authorizationGrantTypes(dto.getAuthorizationGrantTypes())
				.redirectUris(dto.getRedirectUris())
				.scopes(dto.getScopes())
				.requireProofKey(dto.isRequireProofKey())
				.build();
		
		return client;
	}
}
