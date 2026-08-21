const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error("DATABASE_URL is not set. The app cannot start without it.");
}

const pool = new Pool({
  connectionString,
  ssl: connectionString && connectionString.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

function q(text, params) {
  return pool.query(text, params);
}

function genJoinCode() {
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}

// 產生匿名動態牆用的暱稱，跟真實姓名／孩子姓名完全無關。
const NICK_ADJ = [
  "溫柔", "耐心", "安靜", "堅定", "溫暖", "細心", "勇敢", "踏實",
  "柔軟", "沉穩", "專注", "體貼", "認真", "從容", "溫和", "堅持"
];
const NICK_NOUN = [
  "小熊", "貓頭鷹", "小鹿", "水獺", "松鼠", "小狐狸", "刺蝟", "白鷺",
  "浣熊", "小兔", "梅花鹿", "貓咪", "海豚", "螢火蟲", "杜鵑", "山雀"
];
function randomNickname() {
  const a = NICK_ADJ[Math.floor(Math.random() * NICK_ADJ.length)];
  const n = NICK_NOUN[Math.floor(Math.random() * NICK_NOUN.length)];
  const suffix = Math.floor(Math.random() * 90 + 10);
  return a + n + suffix;
}

async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS listen21_users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','coach','parent')),
      display_name TEXT NOT NULL,
      wall_nickname TEXT NOT NULL,
      cohort_id INTEGER,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS listen21_cohorts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      join_code TEXT UNIQUE NOT NULL,
      coach_id INTEGER REFERENCES listen21_users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // add the FK from users -> cohorts now that both tables exist
  await q(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'listen21_users_cohort_fk'
      ) THEN
        ALTER TABLE listen21_users
          ADD CONSTRAINT listen21_users_cohort_fk
          FOREIGN KEY (cohort_id) REFERENCES listen21_cohorts(id);
      END IF;
    END $$;
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS listen21_commitments (
      id SERIAL PRIMARY KEY,
      parent_id INTEGER NOT NULL REFERENCES listen21_users(id),
      child_name TEXT NOT NULL,
      relationship TEXT NOT NULL,
      action_text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS listen21_checkins (
      id SERIAL PRIMARY KEY,
      commitment_id INTEGER NOT NULL REFERENCES listen21_commitments(id),
      day_number INTEGER NOT NULL,
      note TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(commitment_id, day_number)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS listen21_likes (
      id SERIAL PRIMARY KEY,
      checkin_id INTEGER NOT NULL REFERENCES listen21_checkins(id),
      user_id INTEGER NOT NULL REFERENCES listen21_users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(checkin_id, user_id)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS listen21_replies (
      id SERIAL PRIMARY KEY,
      checkin_id INTEGER NOT NULL REFERENCES listen21_checkins(id),
      user_id INTEGER NOT NULL REFERENCES listen21_users(id),
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

async function seed({ adminEmail, adminPasswordHash }) {
  const { rows: admins } = await q(
    `SELECT id FROM listen21_users WHERE role = 'admin' LIMIT 1;`
  );
  if (admins.length === 0) {
    await q(
      `INSERT INTO listen21_users (email, password_hash, role, display_name, wall_nickname)
       VALUES ($1, $2, 'admin', '系統管理員', $3)
       ON CONFLICT (email) DO NOTHING;`,
      [adminEmail, adminPasswordHash, randomNickname()]
    );
  }

  const { rows: cohorts } = await q(`SELECT id FROM listen21_cohorts LIMIT 1;`);
  if (cohorts.length === 0) {
    await q(
      `INSERT INTO listen21_cohorts (name, join_code) VALUES ('第一期', 'LISTEN21');`
    );
  }
}

module.exports = { pool, q, migrate, seed, genJoinCode, randomNickname };
