CREATE TABLE IF NOT EXISTS products (
    id integer PRIMARY KEY,
    name text NOT NULL,
    price_cents integer NOT NULL CHECK (price_cents > 0)
);
INSERT INTO products (id, name, price_cents) VALUES
    (1, 'Notebook', 3500), (2, 'Pencil', 500), (3, 'Backpack', 12000)
ON CONFLICT (id) DO NOTHING;
CREATE TABLE IF NOT EXISTS orders (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username text NOT NULL,
    items jsonb NOT NULL,
    total_cents integer NOT NULL CHECK (total_cents > 0),
    created_at timestamptz NOT NULL DEFAULT now()
);
