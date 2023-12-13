/* Creamos algunos usuarios con sus roles */
--INSERT INTO usuario(username, password, expired, locked, credentials_expired, disabled) VALUES ('andres', '', false, false, false, false);
--INSERT INTO usuario(username, password, expired, locked, credentials_expired, disabled) VALUES ('admin', '', false, false, false, false);

INSERT INTO rol(rol) VALUES ('ROLE_ADMIN');
INSERT INTO rol(rol) VALUES ('ROLE_USER');

--INSERT INTO usuario_rol(usuario_id, rol_id) VALUES (1, 1);
--INSERT INTO usuario_rol(usuario_id, rol_id) VALUES (2, 2);
--INSERT INTO usuario_rol(usuario_id, rol_id) VALUES (2, 1);