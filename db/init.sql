-- ============================================================
-- LAB: Blind SQL Injection (Time-Based) - Database Init
-- ============================================================

CREATE TABLE IF NOT EXISTS products (
    id          SERIAL PRIMARY KEY,
    sku         VARCHAR(32) UNIQUE NOT NULL,
    name        VARCHAR(255) NOT NULL,
    category    VARCHAR(64)  NOT NULL,
    price       NUMERIC(10,2) NOT NULL,
    stock       INTEGER DEFAULT 0,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analytics_events (
    id          SERIAL PRIMARY KEY,
    product_id  INTEGER REFERENCES products(id),
    event_type  VARCHAR(64) NOT NULL,   -- 'view', 'add_to_cart', 'purchase'
    user_agent  TEXT,
    country     VARCHAR(3),
    occurred_at TIMESTAMPTZ DEFAULT NOW()
);

-- Secret table that the attacker should discover via blind injection
CREATE TABLE IF NOT EXISTS internal_config (
    key   VARCHAR(128) PRIMARY KEY,
    value TEXT NOT NULL
);

-- Seed products
INSERT INTO products (sku, name, category, price, stock) VALUES
  ('SKU-001', 'Wireless Keyboard MX900',  'peripherals', 89.99,  145),
  ('SKU-002', 'UltraWide Monitor 34"',     'monitors',    549.00,  32),
  ('SKU-003', 'NVMe SSD 2TB',             'storage',     179.50, 210),
  ('SKU-004', 'Gaming Mouse G502X',        'peripherals', 69.99,  88),
  ('SKU-005', 'USB-C Hub 10-in-1',         'accessories', 49.99, 320),
  ('SKU-006', 'Mechanical Keyboard TKL',   'peripherals', 129.00,  60),
  ('SKU-007', 'Webcam 4K Pro',             'peripherals', 199.00,  45),
  ('SKU-008', 'DDR5 RAM 32GB Kit',         'memory',      229.99,  75);

-- Seed analytics events
INSERT INTO analytics_events (product_id, event_type, user_agent, country) VALUES
  (1, 'view',        'Mozilla/5.0 Chrome/120',  'ES'),
  (2, 'view',        'Mozilla/5.0 Firefox/121', 'US'),
  (3, 'add_to_cart', 'Mozilla/5.0 Safari/17',   'GB'),
  (1, 'purchase',    'Mozilla/5.0 Chrome/120',  'ES'),
  (4, 'view',        'Mozilla/5.0 Edge/120',    'DE'),
  (5, 'view',        'Mozilla/5.0 Chrome/120',  'FR'),
  (2, 'purchase',    'Mozilla/5.0 Firefox/121', 'US'),
  (6, 'view',        'curl/8.5',                'CN'),
  (7, 'add_to_cart', 'PostmanRuntime/7.36',     'MX'),
  (3, 'purchase',    'Mozilla/5.0 Chrome/120',  'ES');

-- Secret data (the "flag" for the lab)
INSERT INTO internal_config (key, value) VALUES
  ('db_schema_version', '4.2.1-release'),
  ('admin_api_secret',  'FLAG{bl1nd_sqli_pwn3d_y0u}'),
  ('maintenance_mode',  'false');
