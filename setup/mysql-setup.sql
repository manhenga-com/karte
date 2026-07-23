CREATE DATABASE IF NOT EXISTS mikrotik_vouchers
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'voucher_app'@'localhost'
  IDENTIFIED BY 'change-this-password';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON mikrotik_vouchers.*
  TO 'voucher_app'@'localhost';

FLUSH PRIVILEGES;
