package com.tutorial.authorizationserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tutorial.authorizationserver.entity.Rol;
import com.tutorial.authorizationserver.enums.RoleName;

@Repository
public interface RolRepository extends JpaRepository<Rol, Integer>{
	
	Optional<Rol> findByRol(RoleName roleName);
}
