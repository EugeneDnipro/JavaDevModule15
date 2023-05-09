INSERT INTO users (username, password, enabled)
    VALUES ('user', 'jdbcDefault', 1);

INSERT INTO authorities (username, authority)
    VALUES ('user', 'ADMIN');