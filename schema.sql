-- সব টাকা পয়সায় (পূর্ণ সংখ্যা)। ১ টাকা = ১০০ পয়সা।
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'publisher' CHECK (role IN ('publisher','admin')),
  active boolean NOT NULL DEFAULT true,
  signup_ip text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE wallets (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  verified_paisa  bigint NOT NULL DEFAULT 0 CHECK (verified_paisa  >= 0),
  available_paisa bigint NOT NULL DEFAULT 0 CHECK (available_paisa >= 0),
  pending_paisa   bigint NOT NULL DEFAULT 0 CHECK (pending_paisa   >= 0),
  withdrawn_paisa bigint NOT NULL DEFAULT 0 CHECK (withdrawn_paisa >= 0),
  cycle_started_at timestamptz,
  CHECK (available_paisa + pending_paisa + withdrawn_paisa = verified_paisa)
);

CREATE TABLE ads (
  id bigserial PRIMARY KEY,
  advertiser text NOT NULL,
  title text NOT NULL,
  link text NOT NULL CHECK (link ~ '^https://'),
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ad_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  ad_id bigint NOT NULL REFERENCES ads(id),
  reward_paisa int NOT NULL,
  day date NOT NULL,
  ip text,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX ad_views_user_done ON ad_views (user_id, completed_at) WHERE completed_at IS NOT NULL;

CREATE TABLE withdrawals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  txn_id text UNIQUE NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id),
  amount_paisa bigint NOT NULL CHECK (amount_paisa >= 50000),
  method text NOT NULL CHECK (method IN ('bkash','nagad')),
  wallet_number text NOT NULL,
  holder_name text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','paid','rejected')),
  reference text,
  admin_note text,
  idempotency_key text NOT NULL,
  processed_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, idempotency_key)
);
-- একজন ব্যবহারকারীর একসাথে একটির বেশি চলমান আবেদন থাকবে না
CREATE UNIQUE INDEX one_open_withdrawal ON withdrawals (user_id) WHERE status IN ('pending','approved');
-- একই পেমেন্ট রেফারেন্স দুইবার ব্যবহার করা যাবে না
CREATE UNIQUE INDEX unique_reference ON withdrawals (reference) WHERE reference IS NOT NULL;

CREATE TABLE ledger (
  id bigserial PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  kind text NOT NULL CHECK (kind IN ('ad_earning','withdraw_reserve','withdraw_release','withdraw_paid')),
  amount_paisa bigint NOT NULL,
  ref text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE advertiser_payments (
  id bigserial PRIMARY KEY,
  advertiser text NOT NULL,
  amount_paisa bigint NOT NULL CHECK (amount_paisa > 0),
  reference text UNIQUE NOT NULL,
  recorded_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
