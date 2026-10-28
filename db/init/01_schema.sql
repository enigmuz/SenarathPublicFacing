-- ============================================================================
--  Senarath Bank  |  SIMULATION / SECURITY TRAINING LAB
--  Database schema  (MariaDB)
--
--  *** THIS IS A DELIBERATELY VULNERABLE TRAINING ENVIRONMENT ***
--  *** ALL DATA IS FICTIONAL. NOT A REAL BANK. DO NOT USE REAL DATA. ***
--
--  Two logical databases live on one DB server (mirrors the "Database
--  Servers" tier in the reference architecture):
--     senarath_web   -> general public website + CMS   (DMZ1 Web Server 1)
--     senarath_bank  -> online banking application      (DMZ1 Web Server 2)
--
--  NOTE (intentional weakness): passwords are stored as unsalted MD5 / plain
--  text on purpose, so that credential attacks and cracking are demonstrable
--  and the resulting telemetry can be analysed in the SIEM.
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
--  DATABASE 1 :  senarath_web   (public website / CMS)
-- ============================================================================
CREATE DATABASE IF NOT EXISTS senarath_web
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE senarath_web;

-- Back-office / CMS operators (intentionally weak: unsalted MD5)
CREATE TABLE cms_users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  password_md5  CHAR(32)     NOT NULL,          -- unsalted MD5 on purpose
  full_name     VARCHAR(128),
  email         VARCHAR(128),
  role          VARCHAR(32)  NOT NULL DEFAULT 'editor',  -- editor|admin|superadmin
  status        VARCHAR(16)  NOT NULL DEFAULT 'active',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Editable news / announcements (body is rendered unescaped -> stored XSS)
CREATE TABLE news_articles (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  title         VARCHAR(200) NOT NULL,
  slug          VARCHAR(200) NOT NULL,
  summary       VARCHAR(400),
  body          MEDIUMTEXT,
  author        VARCHAR(128),
  category      VARCHAR(64)  DEFAULT 'News',
  published      TINYINT(1)  NOT NULL DEFAULT 1,
  published_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Public contact form submissions (searched via string-concat SQL -> SQLi)
CREATE TABLE contact_messages (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(128),
  email         VARCHAR(128),
  phone         VARCHAR(32),
  subject       VARCHAR(200),
  message       TEXT,
  src_ip        VARCHAR(64),
  user_agent    VARCHAR(400),
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE newsletter_subscribers (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  email         VARCHAR(128) NOT NULL,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE branches (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(128) NOT NULL,
  city          VARCHAR(64),
  address       VARCHAR(255),
  phone         VARCHAR(32),
  swift         VARCHAR(16),
  lat           DECIMAL(9,6),
  lng           DECIMAL(9,6)
);

CREATE TABLE careers (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  title         VARCHAR(128) NOT NULL,
  department    VARCHAR(64),
  location      VARCHAR(64),
  type          VARCHAR(32)  DEFAULT 'Full-time',
  description   TEXT,
  closing_date  DATE,
  posted_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE job_applications (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  career_id     INT,
  applicant     VARCHAR(128),
  email         VARCHAR(128),
  phone         VARCHAR(32),
  cover_note    TEXT,
  cv_filename   VARCHAR(255),          -- unrestricted upload target
  src_ip        VARCHAR(64),
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- In-database audit trail (in addition to JSON file logs shipped to the SIEM)
CREATE TABLE audit_log (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  ts            DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  event_type    VARCHAR(48),
  severity      VARCHAR(16)  DEFAULT 'info',
  username      VARCHAR(64),
  src_ip        VARCHAR(64),
  http_method   VARCHAR(8),
  path          VARCHAR(255),
  action        VARCHAR(128),
  outcome       VARCHAR(16),
  detail        TEXT
);

-- ============================================================================
--  DATABASE 2 :  senarath_bank   (online banking)
-- ============================================================================
CREATE DATABASE IF NOT EXISTS senarath_bank
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE senarath_bank;

CREATE TABLE customers (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  cust_no       VARCHAR(16)  NOT NULL UNIQUE,
  full_name     VARCHAR(128) NOT NULL,
  nic           VARCHAR(16),               -- fictional Sri Lankan NIC
  email         VARCHAR(128),
  phone         VARCHAR(32),
  address       VARCHAR(255),
  dob           DATE,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Login accounts (intentionally weak: unsalted MD5, no lockout enforced)
CREATE TABLE users (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  customer_id     INT,
  username        VARCHAR(64)  NOT NULL UNIQUE,
  password_md5    CHAR(32)     NOT NULL,       -- unsalted MD5 on purpose
  role            VARCHAR(16)  NOT NULL DEFAULT 'customer',  -- customer|teller|admin
  status          VARCHAR(16)  NOT NULL DEFAULT 'active',
  failed_attempts INT          NOT NULL DEFAULT 0,  -- tracked but NOT enforced
  last_login      DATETIME,
  created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  customer_id   INT          NOT NULL,
  account_no    VARCHAR(20)  NOT NULL UNIQUE,
  account_type  VARCHAR(16)  NOT NULL DEFAULT 'Savings',  -- Savings|Current|FD
  branch        VARCHAR(64),
  balance       DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  currency      VARCHAR(8)   NOT NULL DEFAULT 'LKR',
  status        VARCHAR(16)  NOT NULL DEFAULT 'active',
  opened_at     DATE
);

CREATE TABLE transactions (
  id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
  account_id          INT          NOT NULL,
  ts                  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  txn_type            VARCHAR(16)  NOT NULL,       -- debit|credit|transfer
  amount              DECIMAL(15,2) NOT NULL,
  balance_after       DECIMAL(15,2),
  counterparty_acct   VARCHAR(20),
  counterparty_name   VARCHAR(128),
  memo                VARCHAR(255),                -- rendered unescaped -> stored XSS
  channel             VARCHAR(16)  DEFAULT 'online',
  status              VARCHAR(16)  DEFAULT 'completed',
  reference           VARCHAR(32)
);

CREATE TABLE beneficiaries (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  customer_id   INT          NOT NULL,
  nickname      VARCHAR(64),
  account_no    VARCHAR(20),
  bank          VARCHAR(64),
  payee_name    VARCHAR(128),
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cards (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  customer_id   INT          NOT NULL,
  card_masked   VARCHAR(24),           -- e.g. 4539 **** **** 1234
  card_type     VARCHAR(24),
  expiry        VARCHAR(8),
  status        VARCHAR(16)  DEFAULT 'active'
);

CREATE TABLE support_tickets (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  customer_id   INT,
  subject       VARCHAR(200),
  body          TEXT,                  -- rendered unescaped -> stored XSS
  status        VARCHAR(16)  DEFAULT 'open',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Dedicated authentication log (great brute-force / spray telemetry)
CREATE TABLE login_log (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  ts            DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  username      VARCHAR(64),
  src_ip        VARCHAR(64),
  user_agent    VARCHAR(400),
  outcome       VARCHAR(16),           -- success|failure
  detail        VARCHAR(255)
);

CREATE TABLE audit_log (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  ts            DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  event_type    VARCHAR(48),
  severity      VARCHAR(16)  DEFAULT 'info',
  username      VARCHAR(64),
  src_ip        VARCHAR(64),
  http_method   VARCHAR(8),
  path          VARCHAR(255),
  action        VARCHAR(128),
  outcome       VARCHAR(16),
  detail        TEXT
);

SET FOREIGN_KEY_CHECKS = 1;
