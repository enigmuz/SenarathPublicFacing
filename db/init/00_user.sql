-- ============================================================================
--  Senarath Bank  |  SIMULATION LAB  -  application DB user
--  Runs before the schema files (alphabetical order in initdb.d).
--  Intentionally broad grants + weak password (lab only).
-- ============================================================================
CREATE USER IF NOT EXISTS 'senarath_app'@'%' IDENTIFIED BY 'App@12345';
GRANT ALL PRIVILEGES ON senarath_web.*  TO 'senarath_app'@'%';
GRANT ALL PRIVILEGES ON senarath_bank.* TO 'senarath_app'@'%';
FLUSH PRIVILEGES;
