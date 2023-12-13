package com.tutorial.authorizationserver.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tutorial.authorizationserver.dto.MessageDto;
import com.tutorial.authorizationserver.dto.UsuarioDto;
import com.tutorial.authorizationserver.service.UsuarioService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
	
	private final UsuarioService usuarioService;
	
	@PostMapping("/create")
	public ResponseEntity<MessageDto> crearUsuario(@RequestBody UsuarioDto dto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.crearUsuario(dto));
	}
}
