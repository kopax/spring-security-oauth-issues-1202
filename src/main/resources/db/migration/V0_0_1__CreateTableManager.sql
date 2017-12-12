CREATE TABLE "MANAGER" (
  "ID" BIGSERIAL NOT NULL,
  "LOGIN" VARCHAR(255) DEFAULT NULL,
  "PASSWORD" VARCHAR(255) DEFAULT NULL,
  "AUTHORITIES" VARCHAR(255),
  "VERSION" BIGINT DEFAULT NULL,
  "CREATED_DATE" TIMESTAMP DEFAULT NULL,
  "CREATED_BY" BIGINT DEFAULT NULL,
  "LAST_MODIFIED_DATE" TIMESTAMP DEFAULT NULL,
  "LAST_MODIFIED_BY" BIGINT DEFAULT NULL,
  "ACTIVE" BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY ("ID"),
  CONSTRAINT manager_unique UNIQUE ("LOGIN")
);
