-- ============================================================================
--  Senarath Bank  |  SIMULATION / SECURITY TRAINING LAB
--  Seed data  (ALL FICTIONAL)
-- ============================================================================
SET NAMES utf8mb4;

-- ---------------------------------------------------------------------------
--  senarath_web
-- ---------------------------------------------------------------------------
USE senarath_web;

-- CMS operators  (password shown for the lab in the README)
--   admin        / Admin@123     (superadmin)
--   editor1      / password      (editor)
--   nsenanayake  / senarath2024  (admin)
INSERT INTO cms_users (username, password_md5, full_name, email, role) VALUES
('admin',       '0e7517141fb53f21ee439b355b5a1d0a', 'Site Administrator', 'webadmin@senarathbank.lk', 'superadmin'),
('editor1',     '5f4dcc3b5aa765d61d8327deb882cf99', 'Chamari Edirisinghe', 'editor@senarathbank.lk',   'editor'),
('nsenanayake', '9cc59e7f6844fd76ca376556f341f4c9', 'Nuwan Senanayake',   'nuwan.s@senarathbank.lk',  'admin');

INSERT INTO branches (name, city, address, phone, swift, lat, lng) VALUES
('Head Office',        'Colombo 01', 'No. 42, Sir Baron Jayatilaka Mawatha, Colombo 01',        '+94 11 2 440 440', 'SENBLKLX',    6.933100, 79.842800),
('Kandy Branch',       'Kandy',      'No. 15, Dalada Veediya, Kandy',                            '+94 81 2 234 567', 'SENBLKLXKDY', 7.293700, 80.635700),
('Galle Branch',       'Galle',      'No. 88, Wakwella Road, Galle',                             '+94 91 2 223 344', 'SENBLKLXGLE', 6.053700, 80.220800),
('Jaffna Branch',      'Jaffna',     'No. 120, Hospital Road, Jaffna',                           '+94 21 2 221 100', 'SENBLKLXJAF', 9.661500, 80.025500),
('Negombo Branch',     'Negombo',    'No. 7, Sea Street, Negombo',                               '+94 31 2 222 888', 'SENBLKLXNEG', 7.208300, 79.838700),
('Matara Branch',      'Matara',     'No. 55, Anagarika Dharmapala Mawatha, Matara',             '+94 41 2 222 555', 'SENBLKLXMAT', 5.948500, 80.535300),
('Kurunegala Branch',  'Kurunegala', 'No. 23, Colombo Road, Kurunegala',                         '+94 37 2 221 777', 'SENBLKLXKUR', 7.486700, 80.362500),
('Batticaloa Branch',  'Batticaloa', 'No. 19, Trinco Road, Batticaloa',                          '+94 65 2 222 333', 'SENBLKLXBAT', 7.717000, 81.700000);

INSERT INTO news_articles (title, slug, summary, body, author, category, published_at) VALUES
('Senarath Bank reports strong first-half growth', 'h1-growth-2026',
 'The bank posted a 14% rise in deposits for the first half of 2026.',
 '<p>Senarath Bank today announced results for the first half of 2026, with total deposits growing 14% year on year and the loan book expanding across SME and retail segments.</p><p>"Our digital-first strategy continues to pay off," said the CEO.</p>',
 'Corporate Communications', 'Press Release', '2026-07-15 09:30:00'),
('New SenNet online banking experience now live', 'sennet-relaunch',
 'A refreshed online banking portal with faster transfers and a new dashboard.',
 '<p>Our redesigned <strong>SenNet</strong> online banking portal is now available to all retail customers, featuring a modern dashboard, quick transfers, and e-statements.</p>',
 'Digital Banking', 'Product', '2026-09-02 11:00:00'),
('Senarath Bank opens new branch in Batticaloa', 'batticaloa-branch',
 'Our 8th branch brings full-service banking to the Eastern Province.',
 '<p>We are pleased to open our newest branch in Batticaloa, expanding access to savings, loans, and SME banking in the Eastern Province.</p>',
 'Corporate Communications', 'News', '2026-10-10 10:00:00'),
('Stay safe: how we will (and will not) contact you', 'security-awareness-2026',
 'Tips to protect yourself from phishing and fraud.',
 '<p>Senarath Bank will never ask for your password or OTP by phone or email. Always check the address bar before logging in.</p>',
 'Information Security', 'Security', '2026-10-20 08:00:00');

INSERT INTO careers (title, department, location, type, description, closing_date) VALUES
('Software Engineer - Digital Banking', 'IT', 'Colombo 01', 'Full-time', 'Build and maintain our online and mobile banking platforms. Python/Java, REST APIs, SQL.', '2026-12-15'),
('Branch Manager', 'Retail Banking', 'Kandy', 'Full-time', 'Lead the Kandy branch team and drive deposit and lending growth.', '2026-11-30'),
('Information Security Analyst', 'Information Security', 'Colombo 01', 'Full-time', 'Monitor security events, support SOC operations, and assist with incident response.', '2026-12-05'),
('Customer Service Officer', 'Operations', 'Galle', 'Full-time', 'Front-line customer service and account operations at the Galle branch.', '2026-11-20');

INSERT INTO newsletter_subscribers (email) VALUES
('kamal.perera@gmail.com'), ('n.silva@yahoo.com'), ('info.saman@outlook.com'), ('anoma.j@gmail.com');

INSERT INTO contact_messages (name, email, phone, subject, message, src_ip, user_agent) VALUES
('Ruwan Jayasuriya', 'ruwanj@gmail.com', '+94 77 123 4567', 'Loan inquiry', 'I would like to know about your housing loan rates.', '112.134.55.11', 'Mozilla/5.0'),
('Priya Nadarajah', 'priya.n@gmail.com', '+94 71 998 2211', 'ATM issue', 'The ATM at Jaffna branch retained my card yesterday.', '175.157.88.9', 'Mozilla/5.0'),
('Malinda Cooray', 'malinda@live.com', '+94 76 555 1212', 'Fixed deposit', 'What are your current 1-year FD rates?', '123.231.21.45', 'Mozilla/5.0');

-- ---------------------------------------------------------------------------
--  senarath_bank
-- ---------------------------------------------------------------------------
USE senarath_bank;

INSERT INTO customers (cust_no, full_name, nic, email, phone, address, dob) VALUES
('CUS00001','Kamal Perera',          '851234567V','kamal.perera@gmail.com','+94 77 123 4567','No. 12, Temple Road, Maharagama','1985-04-12'),
('CUS00002','Nimal Silva',           '902345678V','n.silva@yahoo.com',     '+94 71 234 5678','No. 5, Galle Road, Dehiwala','1990-08-23'),
('CUS00003','Saman Fernando',        '783456789V','saman.f@outlook.com',   '+94 76 345 6789','No. 88, Main Street, Negombo','1978-01-30'),
('CUS00004','Anoma Jayawardena',     '896543210V','anoma.j@gmail.com',     '+94 77 456 7890','No. 21, Kandy Road, Kadawatha','1989-11-05'),
('CUS00005','Dinesh Bandara',        '941122334V','dinesh.b@gmail.com',    '+94 70 567 8901','No. 3, Lake Road, Kurunegala','1994-06-18'),
('CUS00006','Chathura Wickramasinghe','871239876V','chathuraw@gmail.com',  '+94 71 678 9012','No. 44, Hill Street, Kandy','1987-03-09'),
('CUS00007','Ishara Rajapaksa',      '925566778V','ishara.r@yahoo.com',    '+94 76 789 0123','No. 67, Beach Road, Matara','1992-09-27'),
('CUS00008','Tharindu Gunawardena',  '803344556V','tharindu.g@gmail.com',  '+94 77 890 1234','No. 9, Station Road, Galle','1980-12-14'),
('CUS00009','Malini Senanayake',     '776655443V','malini.s@outlook.com',  '+94 71 901 2345','No. 31, Flower Road, Colombo 07','1977-05-21'),
('CUS00010','Ruwan Dissanayake',     '911199887V','ruwan.d@gmail.com',     '+94 70 012 3456','No. 18, Park Avenue, Nugegoda','1991-02-16'),
('CUS00011','Nadeeka Herath',        '865544332V','nadeeka.h@gmail.com',   '+94 76 223 4455','No. 72, Market Road, Anuradhapura','1986-07-03'),
('CUS00012','Sunil Weerasinghe',     '722233445V','sunil.w@yahoo.com',     '+94 77 334 5566','No. 6, Hospital Road, Badulla','1972-10-29');

-- Login accounts. Credentials are listed in the README (lab use).
--   customers use weak passwords; admin/teller are staff.
INSERT INTO users (customer_id, username, password_md5, role, status, last_login) VALUES
(1,  'kperera',       '482c811da5d5b4bc6d497ffa98491e38', 'customer', 'active', '2026-10-27 19:12:00'),
(2,  'nsilva',        'e10adc3949ba59abbe56e057f20f883e', 'customer', 'active', '2026-10-26 08:45:00'),
(3,  'sfernando',     '3fc0a7acf087f549ac2b266baf94b8b1', 'customer', 'active', '2026-10-25 14:03:00'),
(4,  'ajayawardena',  '3cd63bcc7e531cf24b35a0e5a366e408', 'customer', 'active', '2026-10-27 21:30:00'),
(5,  'dbandara',      '72ea9b10ad081b41a57c4982649ee7fd', 'customer', 'active', '2026-10-24 10:10:00'),
(6,  'cwickrama',     '221305e7e80571e7fb6181b1cbf70b94', 'customer', 'active', '2026-10-27 07:55:00'),
(7,  'irajapaksa',    'f25a2fc72690b780b2a14e140ef6a9e0', 'customer', 'active', '2026-10-20 16:40:00'),
(8,  'tgunawardena',  'd28968f457b86b01e8eee41df3783786', 'customer', 'active', '2026-10-22 12:20:00'),
(9,  'msenanayake',   'd6b0ab7f1c8ab8f514db9a6d85de160a', 'customer', 'active', '2026-10-26 18:05:00'),
(10, 'rdissanayake',  '0d107d09f5bbe40cade3de5c71e9e9b7', 'customer', 'active', '2026-10-27 22:00:00'),
(11, 'nherath',       '201f00b5ca5d65a1c118e5e32431514c', 'customer', 'active', '2026-10-23 09:30:00'),
(12, 'sweerasinghe',  '5f4dcc3b5aa765d61d8327deb882cf99', 'customer', 'active', '2026-10-21 11:15:00'),
(NULL,'teller1',      'd331df02bf777750f59835c4bd9b01d9', 'teller',   'active', '2026-10-28 08:00:00'),
(NULL,'admin',        '0192023a7bbd73250516f069df18b500', 'admin',    'active', '2026-10-28 08:30:00');

-- Accounts (balances in LKR)
INSERT INTO accounts (customer_id, account_no, account_type, branch, balance, currency, status, opened_at) VALUES
(1, '1001000001','Savings','Head Office', 125450.75,'LKR','active','2019-03-11'),
(1, '1001000002','Current','Head Office', 342000.00,'LKR','active','2020-06-01'),
(2, '1001000003','Savings','Dehiwala',     58230.40,'LKR','active','2018-09-15'),
(3, '1001000004','Savings','Negombo',     981200.10,'LKR','active','2017-01-20'),
(3, '1001000005','FD',     'Negombo',    2500000.00,'LKR','active','2024-02-01'),
(4, '1001000006','Savings','Kadawatha',   43750.00,'LKR','active','2021-11-30'),
(5, '1001000007','Savings','Kurunegala',  12980.55,'LKR','active','2022-05-19'),
(6, '1001000008','Current','Kandy',       76540.90,'LKR','active','2020-08-08'),
(7, '1001000009','Savings','Matara',     210300.25,'LKR','active','2019-12-02'),
(8, '1001000010','Savings','Galle',       33200.00,'LKR','active','2023-03-14'),
(9, '1001000011','Current','Colombo 07', 1540000.00,'LKR','active','2016-07-07'),
(10,'1001000012','Savings','Nugegoda',    89450.65,'LKR','active','2021-02-28'),
(11,'1001000013','Savings','Anuradhapura',27600.00,'LKR','active','2022-10-10'),
(12,'1001000014','Savings','Badulla',    455000.00,'LKR','active','2015-04-25');

-- Transaction history (recent activity; memos render unescaped -> stored XSS lab)
INSERT INTO transactions (account_id, ts, txn_type, amount, balance_after, counterparty_acct, counterparty_name, memo, channel, status, reference) VALUES
(1,'2026-10-20 09:14:00','credit',  85000.00,110450.75, NULL,'Salary - Ceylon Textiles','October salary','online','completed','SAL202610'),
(1,'2026-10-21 13:20:00','debit',    4500.00,105950.75,'7788990011','CEB Electricity','Electricity bill','online','completed','UTIL88231'),
(1,'2026-10-23 18:45:00','transfer',15000.00, 90950.75,'1001000003','Nimal Silva','Loan repayment','online','completed','TRF553201'),
(1,'2026-10-26 10:05:00','credit',  34500.00,125450.75, NULL,'Freelance - WebWorks','Project payment','online','completed','INV772312'),
(3,'2026-10-19 08:00:00','credit',  22000.00, 80230.40, NULL,'Pension Dept','Monthly pension','online','completed','PEN202610'),
(3,'2026-10-23 18:45:00','credit',  15000.00, 95230.40,'1001000001','Kamal Perera','Loan repayment','online','completed','TRF553201'),
(3,'2026-10-25 12:30:00','debit',   37000.00, 58230.40,'5566778899','Singer Sri Lanka','Refrigerator','online','completed','POS901233'),
(4,'2026-10-18 09:00:00','credit', 950000.00,981200.10, NULL,'Property sale','Land sale advance','branch','completed','DEP110293'),
(4,'2026-10-22 15:10:00','debit',   50000.00,931200.10,'1234509876','Insurance Co','Vehicle insurance','online','completed','INS334455'),
(6,'2026-10-15 11:11:00','credit',  40000.00, 83750.00, NULL,'Salary','September salary','online','completed','SAL202609'),
(6,'2026-10-24 17:00:00','debit',   40000.00, 43750.00,'9988776655','Keells Super','Monthly groceries','online','completed','POS556677'),
(8,'2026-10-20 10:30:00','credit',  60000.00, 96540.90, NULL,'Salary','Salary','online','completed','SAL202610B'),
(8,'2026-10-26 09:45:00','transfer',20000.00, 76540.90,'1001000011','Malini Senanayake','Rent','online','completed','TRF778812'),
(11,'2026-10-21 14:00:00','credit',120000.00,330300.25, NULL,'Export income','Tea export','branch','completed','EXP220114'),
(11,'2026-10-26 09:45:00','credit', 20000.00,210300.25,'1001000010','Tharindu Gunawardena','Rent','online','completed','TRF778812'),
(12,'2026-10-17 08:30:00','debit',   9500.00, 79950.65,'3344556677','Dialog Axiata','Mobile bill','online','completed','UTIL44556'),
(12,'2026-10-24 19:20:00','credit',  9500.00, 89450.65, NULL,'Refund','Service refund','online','completed','RFD889900');

INSERT INTO beneficiaries (customer_id, nickname, account_no, bank, payee_name) VALUES
(1,'Nimal (friend)','1001000003','Senarath Bank','Nimal Silva'),
(1,'CEB bill','7788990011','Peoples Bank','Ceylon Electricity Board'),
(4,'Insurance','1234509876','Commercial Bank','Ceylinco Insurance'),
(8,'Landlord','1001000011','Senarath Bank','Malini Senanayake');

INSERT INTO cards (customer_id, card_masked, card_type, expiry, status) VALUES
(1,'4539 **** **** 1234','Visa Debit','08/28','active'),
(4,'5412 **** **** 9876','Mastercard Debit','11/27','active'),
(9,'4716 **** **** 4421','Visa Platinum','03/29','active');

INSERT INTO support_tickets (customer_id, subject, body, status) VALUES
(2,'Cannot see e-statement','My September e-statement is not loading in the portal.','open'),
(5,'Change mobile number','I need to update my registered mobile number please.','open');
