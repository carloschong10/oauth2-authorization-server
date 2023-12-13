package com.tutorial.authorizationserver.dto;

import java.util.List;

public record UsuarioDto (
	String username,
	String password,
	List<String> roles) {}