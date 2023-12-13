package com.tutorial.authorizationserver.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tutorial.authorizationserver.dto.MessageDto;
import com.tutorial.authorizationserver.dto.UsuarioDto;
import com.tutorial.authorizationserver.entity.Rol;
import com.tutorial.authorizationserver.entity.Usuario;
import com.tutorial.authorizationserver.enums.RoleName;
import com.tutorial.authorizationserver.repository.RolRepository;
import com.tutorial.authorizationserver.repository.UsuarioRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class UsuarioService {
	
	private final UsuarioRepository usuarioRepository;
	private final RolRepository repository;
	private final PasswordEncoder passwordEncoder;
	
	public MessageDto crearUsuario(UsuarioDto dto) {
		Usuario usuario = Usuario.builder()
				.username(dto.username())
				.password(passwordEncoder.encode(dto.password()))
				.build();
		
		Set<Rol> roles = new HashSet<>();		
		dto.roles().forEach(r -> {
			Rol rol = repository.findByRol(RoleName.valueOf(r))
					.orElseThrow(()-> new RuntimeException("Rol no encontrado xD"));
			roles.add(rol);
		});
		
		usuario.setRoles(roles);
		
		usuarioRepository.save(usuario);
		
		return new MessageDto("usuario: " + usuario.getUsername() + " guardado");
	}
	
}
