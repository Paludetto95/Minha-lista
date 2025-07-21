CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 3b265de4f1d7

CREATE TABLE banco (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    PRIMARY KEY (id)
);

CREATE TABLE convenio (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    PRIMARY KEY (id)
);

CREATE TABLE produto (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    name VARCHAR(100) NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

CREATE TABLE proposta (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    PRIMARY KEY (id)
);

CREATE TABLE situacao (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    PRIMARY KEY (id)
);

CREATE TABLE tabulation (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    name VARCHAR(100) NOT NULL, 
    color VARCHAR(7), 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

CREATE TABLE tipo_de_operacao (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    PRIMARY KEY (id)
);

CREATE TABLE user (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    username VARCHAR(64), 
    email VARCHAR(120), 
    password_hash VARCHAR(256), 
    is_admin BOOL, 
    wallet_limit INTEGER NOT NULL, 
    daily_pull_limit INTEGER NOT NULL, 
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_user_email ON user (email);

CREATE UNIQUE INDEX ix_user_username ON user (username);

CREATE TABLE layout_mailing (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    name VARCHAR(100) NOT NULL, 
    produto_id INTEGER NOT NULL, 
    mapping JSON NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(produto_id) REFERENCES produto (id), 
    UNIQUE (name)
);

CREATE INDEX ix_layout_mailing_produto_id ON layout_mailing (produto_id);

CREATE TABLE mailing_batch (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    timestamp DATETIME, 
    filename VARCHAR(255), 
    produto_id INTEGER NOT NULL, 
    user_id INTEGER NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(produto_id) REFERENCES produto (id), 
    FOREIGN KEY(user_id) REFERENCES user (id)
);

CREATE INDEX ix_mailing_batch_produto_id ON mailing_batch (produto_id);

CREATE INDEX ix_mailing_batch_timestamp ON mailing_batch (timestamp);

CREATE INDEX ix_mailing_batch_user_id ON mailing_batch (user_id);

CREATE TABLE `lead` (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    nome_cliente VARCHAR(150), 
    cpf VARCHAR(11) NOT NULL, 
    telefone VARCHAR(20), 
    telefone_2 VARCHAR(20), 
    status VARCHAR(20), 
    data_criacao DATETIME, 
    data_tabulacao DATETIME, 
    additional_data JSON, 
    consultor_id INTEGER, 
    tabulation_id INTEGER, 
    produto_id INTEGER, 
    estado VARCHAR(2), 
    batch_id INTEGER NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(batch_id) REFERENCES mailing_batch (id), 
    FOREIGN KEY(consultor_id) REFERENCES user (id), 
    FOREIGN KEY(produto_id) REFERENCES produto (id), 
    FOREIGN KEY(tabulation_id) REFERENCES tabulation (id)
);

CREATE INDEX ix_lead_batch_id ON `lead` (batch_id);

CREATE INDEX ix_lead_consultor_id ON `lead` (consultor_id);

CREATE UNIQUE INDEX ix_lead_cpf ON `lead` (cpf);

CREATE INDEX ix_lead_data_criacao ON `lead` (data_criacao);

CREATE INDEX ix_lead_estado ON `lead` (estado);

CREATE INDEX ix_lead_nome_cliente ON `lead` (nome_cliente);

CREATE INDEX ix_lead_produto_id ON `lead` (produto_id);

CREATE INDEX ix_lead_status ON `lead` (status);

CREATE INDEX ix_lead_tabulation_id ON `lead` (tabulation_id);

CREATE TABLE lead_consumption (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    user_id INTEGER NOT NULL, 
    lead_id INTEGER NOT NULL, 
    timestamp DATETIME, 
    PRIMARY KEY (id), 
    FOREIGN KEY(lead_id) REFERENCES `lead` (id), 
    FOREIGN KEY(user_id) REFERENCES user (id)
);

CREATE INDEX ix_lead_consumption_lead_id ON lead_consumption (lead_id);

CREATE INDEX ix_lead_consumption_user_id ON lead_consumption (user_id);

INSERT INTO alembic_version (version_num) VALUES ('3b265de4f1d7');

