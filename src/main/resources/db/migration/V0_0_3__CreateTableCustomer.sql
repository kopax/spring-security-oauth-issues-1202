CREATE TABLE "CUSTOMER" (
  "ID" BIGSERIAL NOT NULL,
  "FIRST_NAME" VARCHAR(50) DEFAULT NULL,
  "LAST_NAME" VARCHAR(100) DEFAULT NULL,
  "PRINCIPAL_PHONE" VARCHAR(100) DEFAULT NULL,
  "PRINCIPAL_ADDRESS" VARCHAR(255) DEFAULT NULL,
  "COMPANY_ID" BIGINT NOT NULL,
  "VERSION" BIGINT DEFAULT NULL,
  "CREATED_DATE" TIMESTAMP DEFAULT NULL,
  "CREATED_BY" BIGINT DEFAULT NULL,
  "LAST_MODIFIED_DATE" TIMESTAMP DEFAULT NULL,
  "LAST_MODIFIED_BY" BIGINT DEFAULT NULL,
  "ACTIVE" BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT company_fk FOREIGN KEY("COMPANY_ID") REFERENCES "COMPANY"("ID"),
  PRIMARY KEY ("ID")
);
