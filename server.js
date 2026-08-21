const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { q, migrate, seed, genJoinCode, randomNickname } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const TOTAL_DAYS = 21;

app.set("view engine", "ejs");
app.set("views", __dirname);
app.use(express.urlencoded({ extended: true }));
app.get("/style.css", (req, res) => res.sendFile(path.join(__dirname, "style.css")));
app.use(cookieParser());

// ---------- helpers ----------
function computeDay(startDate) {
  const start = new Date(startDate);
  const startUTC = Date.UTC(start.getFullYear(), start.getMonth(), start.getDate());
  const now = new Date();
  const nowUTC = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
  const diffDays = Math.floor((nowUTC - startUTC) / 86400000);
  return diffDays + 1;
}

function signSession(u) {
  return jwt.sign({ id: u.id, role: u.role }, JWT_SECRET, { expiresIn: "30d" });
}

async function loadUser(req, res, next) {
  req.user = null;
  const token = req.cookies.session;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const { rows } = await q("SELECT * FROM listen21_users WHERE id=$1", [payload.id]);
      if (rows[0]) req.user = rows[0];
    } catch (e) {
      // invalid/expired token, ignore
    }
  }
  next();
}
app.use(loadUser);

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.redirect("/login");
    if (!roles.includes(req.user.role)) return res.status(403).send("沒有權限查看這個頁面");
    next();
  };
}

async function replyMapFor(checkinIds) {
  const map = {};
  if (checkinIds.length === 0) return map;
  const { rows } = await q(
    `SELECT r.checkin_id, r.body, r.created_at, u.role, u.display_name
     FROM listen21_replies r JOIN listen21_users u ON u.id = r.user_id
     WHERE r.checkin_id = ANY($1)
     ORDER BY r.created_at ASC;`,
    [checkinIds]
  );
  rows.forEach((r) => {
    if (!map[r.checkin_id]) map[r.checkin_id] = [];
    const isStaff = r.role === "coach" || r.role === "teacher";
    map[r.checkin_id].push({
      body: r.body,
      isCoach: isStaff,
      roleLabel: r.role === "coach" ? "指導師" : r.role === "teacher" ? "老師" : null,
      nickname: r.display_name
    });
  });
  return map;
}

// ---------- auth ----------
app.get("/login", (req, res) => {
  if (req.user) return res.redirect("/");
  res.render("login", { error: null, email: "" });
});

app.post("/login", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  const { rows } = await q("SELECT * FROM listen21_users WHERE email=$1", [email]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    return res.render("login", { error: "Email 或密碼不正確", email });
  }
  res.cookie("session", signSession(u), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  res.clearCookie("session");
  res.redirect("/login");
});

app.get("/register", (req, res) => {
  if (req.user) return res.redirect("/");
  res.render("register", { error: null, email: "", real_name: "", display_name: "", join_code: "" });
});

app.post("/register", async (req, res) => {
  const real_name = (req.body.real_name || "").trim();
  const nicknameInput = (req.body.display_name || "").trim();
  const display_name = nicknameInput || real_name;
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  const join_code = (req.body.join_code || "").trim().toUpperCase();

  const formState = { real_name, display_name: nicknameInput, email, join_code };

  if (!real_name || !email || password.length < 6 || !join_code) {
    return res.render("register", { error: "請完整填寫表單，密碼至少6碼", ...formState });
  }

  const { rows: cohortRows } = await q("SELECT id FROM listen21_cohorts WHERE join_code=$1", [join_code]);
  if (cohortRows.length === 0) {
    return res.render("register", { error: "邀請碼不正確，請跟指導師確認", ...formState });
  }

  const { rows: existing } = await q("SELECT id FROM listen21_users WHERE email=$1", [email]);
  if (existing.length > 0) {
    return res.render("register", { error: "這個 email 已經註冊過了，請直接登入", ...formState });
  }

  const password_hash = await bcrypt.hash(password, 10);
  const { rows } = await q(
    `INSERT INTO listen21_users (email, password_hash, role, display_name, real_name, wall_nickname, cohort_id)
     VALUES ($1,$2,'parent',$3,$4,$5,$6) RETURNING *;`,
    [email, password_hash, display_name, real_name, randomNickname(), cohortRows[0].id]
  );
  res.cookie("session", signSession(rows[0]), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
  res.redirect("/parent");
});

app.get("/", (req, res) => {
  if (!req.user) return res.redirect("/login");
  if (req.user.role === "parent") return res.redirect("/parent");
  if (req.user.role === "coach" || req.user.role === "teacher") return res.redirect("/coach");
  if (req.user.role === "admin") return res.redirect("/admin");
  res.redirect("/login");
});

// ---------- parent ----------
app.get("/parent", requireRole("parent"), async (req, res) => {
  const { rows } = await q(
    `SELECT c.*, (SELECT COUNT(*) FROM listen21_checkins ci WHERE ci.commitment_id=c.id)::int AS done_count
     FROM listen21_commitments c WHERE c.parent_id=$1 ORDER BY c.created_at DESC;`,
    [req.user.id]
  );
  res.render("parent-list", { user: req.user, commitments: rows, flash: null });
});

app.get("/parent/new", requireRole("parent"), (req, res) => {
  res.render("commitment-new", { user: req.user, error: null });
});

app.post("/parent/new", requireRole("parent"), async (req, res) => {
  const child_name = (req.body.child_name || "").trim();
  const relationship = (req.body.relationship || "").trim();
  const action_text = (req.body.action_text || "").trim();

  if (!child_name || !relationship || action_text.length < 6) {
    return res.render("commitment-new", { user: req.user, error: "請完整填寫，「願意做到」請寫得具體一點（至少6個字）" });
  }

  const { rows } = await q(
    `INSERT INTO listen21_commitments (parent_id, child_name, relationship, action_text)
     VALUES ($1,$2,$3,$4) RETURNING id;`,
    [req.user.id, child_name, relationship, action_text]
  );
  res.redirect("/parent/" + rows[0].id);
});

app.get("/parent/:id", requireRole("parent"), async (req, res) => {
  const { rows } = await q("SELECT * FROM listen21_commitments WHERE id=$1 AND parent_id=$2", [
    req.params.id,
    req.user.id
  ]);
  const commitment = rows[0];
  if (!commitment) return res.status(404).send("找不到這筆承諾卡");

  const { rows: checkins } = await q(
    "SELECT * FROM listen21_checkins WHERE commitment_id=$1 ORDER BY day_number ASC",
    [commitment.id]
  );
  const doneCount = checkins.length;
  const isComplete = doneCount >= TOTAL_DAYS;
  const currentDay = Math.min(computeDay(commitment.created_at), TOTAL_DAYS);
  const windowClosed = !isComplete && computeDay(commitment.created_at) > TOTAL_DAYS;
  const todayCheckin = checkins.find((c) => c.day_number === currentDay) || null;
  const doneDays = checkins.map((c) => c.day_number);

  res.render("parent-dashboard", {
    user: req.user,
    commitment,
    checkins,
    doneCount,
    isComplete,
    currentDay,
    windowClosed,
    todayCheckin,
    doneDays,
    error: null
  });
});

app.post("/parent/:id/checkin", requireRole("parent"), async (req, res) => {
  const { rows } = await q("SELECT * FROM listen21_commitments WHERE id=$1 AND parent_id=$2", [
    req.params.id,
    req.user.id
  ]);
  const commitment = rows[0];
  if (!commitment) return res.status(404).send("找不到這筆承諾卡");

  const note = (req.body.note || "").trim();
  const currentDay = Math.min(computeDay(commitment.created_at), TOTAL_DAYS);

  if (note.length < 2) {
    return res.redirect("/parent/" + commitment.id);
  }

  try {
    await q(
      "INSERT INTO listen21_checkins (commitment_id, day_number, note) VALUES ($1,$2,$3)",
      [commitment.id, currentDay, note]
    );
  } catch (e) {
    // unique violation = already checked in today, ignore silently
  }
  res.redirect("/parent/" + commitment.id);
});

// ---------- wall (parent + coach + teacher) ----------
async function cohortIdsFor(user) {
  if (user.role === "parent") return user.cohort_id ? [user.cohort_id] : [];
  if (user.role === "coach" || user.role === "admin") {
    // 指導師 (chief instructor) and 系統管理員 both oversee every cohort,
    // regardless of which teacher it's assigned to.
    const { rows } = await q("SELECT id FROM listen21_cohorts");
    return rows.map((r) => r.id);
  }
  if (user.role === "teacher") {
    const { rows } = await q("SELECT id FROM listen21_cohorts WHERE coach_id=$1", [user.id]);
    return rows.map((r) => r.id);
  }
  return [];
}

app.get("/wall", requireRole("parent", "coach", "teacher"), async (req, res) => {
  const cohortIds = await cohortIdsFor(req.user);
  if (cohortIds.length === 0) {
    return res.render("wall", { user: req.user, active: "wall", posts: [] });
  }

  const { rows } = await q(
    `SELECT ci.id, ci.day_number, ci.note, u.id AS parent_user_id, u.display_name
     FROM listen21_checkins ci
     JOIN listen21_commitments c ON c.id = ci.commitment_id
     JOIN listen21_users u ON u.id = c.parent_id
     WHERE u.cohort_id = ANY($1)
     ORDER BY ci.created_at DESC
     LIMIT 60;`,
    [cohortIds]
  );

  const ids = rows.map((r) => r.id);
  const [likeRows, myLikeRows, replyMap] = await Promise.all([
    ids.length
      ? q(
          `SELECT checkin_id, COUNT(*)::int AS cnt FROM listen21_likes WHERE checkin_id = ANY($1) GROUP BY checkin_id`,
          [ids]
        )
      : { rows: [] },
    ids.length
      ? q(`SELECT checkin_id FROM listen21_likes WHERE checkin_id = ANY($1) AND user_id=$2`, [ids, req.user.id])
      : { rows: [] },
    replyMapFor(ids)
  ]);

  const likeCountMap = {};
  likeRows.rows.forEach((r) => (likeCountMap[r.checkin_id] = r.cnt));
  const likedSet = new Set(myLikeRows.rows.map((r) => r.checkin_id));

  const posts = rows.map((r) => ({
    id: r.id,
    day_number: r.day_number,
    note: r.note,
    nickname: r.display_name,
    isCoach: false,
    mine: req.user.role === "parent" && r.parent_user_id === req.user.id,
    likeCount: likeCountMap[r.id] || 0,
    liked: likedSet.has(r.id),
    replies: replyMap[r.id] || []
  }));

  res.render("wall", { user: req.user, active: "wall", posts });
});

app.post("/wall/:checkinId/like", requireRole("parent", "coach", "teacher"), async (req, res) => {
  const checkinId = req.params.checkinId;
  try {
    await q("INSERT INTO listen21_likes (checkin_id, user_id) VALUES ($1,$2)", [checkinId, req.user.id]);
  } catch (e) {
    // already liked -> unlike (toggle)
    await q("DELETE FROM listen21_likes WHERE checkin_id=$1 AND user_id=$2", [checkinId, req.user.id]);
  }
  res.redirect("/wall");
});

app.post("/wall/:checkinId/reply", requireRole("parent", "coach", "teacher"), async (req, res) => {
  const body = (req.body.body || "").trim();
  if (body) {
    await q("INSERT INTO listen21_replies (checkin_id, user_id, body) VALUES ($1,$2,$3)", [
      req.params.checkinId,
      req.user.id,
      body
    ]);
  }
  res.redirect("/wall");
});

app.get("/leaderboard", requireRole("parent", "coach", "teacher"), async (req, res) => {
  const cohortIds = await cohortIdsFor(req.user);
  let entries = [];
  if (cohortIds.length) {
    const { rows } = await q(
      `WITH per_commitment AS (
         SELECT c.id AS commitment_id, u.id AS parent_user_id, u.display_name,
                COUNT(ci.id)::int AS done_count,
                MAX(ci.created_at) AS last_checkin_at
         FROM listen21_commitments c
         JOIN listen21_users u ON u.id = c.parent_id
         JOIN listen21_checkins ci ON ci.commitment_id = c.id
         WHERE u.cohort_id = ANY($1)
         GROUP BY c.id, u.id, u.display_name
       ),
       best_per_parent AS (
         SELECT DISTINCT ON (parent_user_id) parent_user_id, display_name, done_count, last_checkin_at
         FROM per_commitment
         ORDER BY parent_user_id, done_count DESC, last_checkin_at ASC
       )
       SELECT * FROM best_per_parent
       ORDER BY done_count DESC, last_checkin_at ASC;`,
      [cohortIds]
    );
    entries = rows.map((r) => ({
      nickname: r.display_name,
      mine: req.user.role === "parent" && r.parent_user_id === req.user.id,
      doneCount: r.done_count,
      isComplete: r.done_count >= TOTAL_DAYS
    }));
  }
  res.render("leaderboard", { user: req.user, active: "leaderboard", entries, totalDays: TOTAL_DAYS });
});

// ---------- coach / teacher ----------
app.get("/coach", requireRole("coach", "teacher"), async (req, res) => {
  const { rows: cohorts } =
    req.user.role === "coach"
      ? await q(
          `SELECT co.*, u.display_name AS teacher_name
           FROM listen21_cohorts co
           LEFT JOIN listen21_users u ON u.id = co.coach_id
           ORDER BY co.created_at;`
        )
      : await q("SELECT * FROM listen21_cohorts WHERE coach_id=$1 ORDER BY created_at", [req.user.id]);

  for (const cohort of cohorts) {
    const { rows } = await q(
      `SELECT c.id, c.child_name, c.created_at, u.real_name AS parent_name, u.display_name AS parent_nickname,
              (SELECT COUNT(*) FROM listen21_checkins ci WHERE ci.commitment_id=c.id)::int AS done_count
       FROM listen21_commitments c JOIN listen21_users u ON u.id = c.parent_id
       WHERE u.cohort_id=$1 ORDER BY c.created_at DESC;`,
      [cohort.id]
    );
    cohort.commitments = rows.map((c) => {
      const nowDay = computeDay(c.created_at);
      const expected = Math.min(Math.max(nowDay - 1, 0), TOTAL_DAYS);
      return { ...c, stalled: c.done_count < expected };
    });

    const { rows: notStarted } = await q(
      `SELECT u.id, u.real_name, u.display_name, u.email, u.created_at
       FROM listen21_users u
       WHERE u.cohort_id=$1 AND u.role='parent'
         AND NOT EXISTS (SELECT 1 FROM listen21_commitments c WHERE c.parent_id = u.id)
       ORDER BY u.created_at DESC;`,
      [cohort.id]
    );
    cohort.notStarted = notStarted;
  }

  res.render("coach", { user: req.user, active: "coach", cohorts });
});

app.get("/coach/commitment/:id", requireRole("coach", "teacher", "admin"), async (req, res) => {
  const { rows } = await q(
    `SELECT c.*, u.real_name AS parent_name, u.display_name AS parent_nickname, u.email AS parent_email, u.cohort_id
     FROM listen21_commitments c JOIN listen21_users u ON u.id = c.parent_id
     WHERE c.id=$1;`,
    [req.params.id]
  );
  const commitment = rows[0];
  if (!commitment) return res.status(404).send("找不到這筆承諾卡");

  const myCohortIds = await cohortIdsFor(req.user);
  if (!myCohortIds.includes(commitment.cohort_id)) {
    return res.status(403).send("這不是你負責的期別");
  }

  const { rows: checkins } = await q(
    "SELECT * FROM listen21_checkins WHERE commitment_id=$1 ORDER BY day_number ASC",
    [commitment.id]
  );
  const replyMap = await replyMapFor(checkins.map((c) => c.id));
  checkins.forEach((c) => (c.replies = replyMap[c.id] || []));

  res.render("coach-commitment", { user: req.user, active: "coach", commitment, checkins });
});

app.post("/coach/checkin/:checkinId/reply", requireRole("coach", "teacher"), async (req, res) => {
  const body = (req.body.body || "").trim();
  const { rows } = await q(
    `SELECT c.id AS commitment_id FROM listen21_checkins ci
     JOIN listen21_commitments c ON c.id = ci.commitment_id
     WHERE ci.id=$1;`,
    [req.params.checkinId]
  );
  if (!rows[0]) return res.status(404).send("找不到這筆打卡");
  if (body) {
    await q("INSERT INTO listen21_replies (checkin_id, user_id, body) VALUES ($1,$2,$3)", [
      req.params.checkinId,
      req.user.id,
      body
    ]);
  }
  res.redirect("/coach/commitment/" + rows[0].commitment_id);
});

// ---------- admin ----------
app.get("/admin", requireRole("admin"), async (req, res) => {
  const { rows: cohorts } = await q(
    `SELECT co.*, u.display_name AS coach_name,
            (SELECT COUNT(*) FROM listen21_users p WHERE p.cohort_id=co.id AND p.role='parent')::int AS parent_count
     FROM listen21_cohorts co LEFT JOIN listen21_users u ON u.id = co.coach_id
     ORDER BY co.created_at;`
  );
  const { rows: coaches } = await q(
    `SELECT u.*, co.id AS cohort_id, co.name AS cohort_name FROM listen21_users u
     LEFT JOIN listen21_cohorts co ON co.coach_id = u.id
     WHERE u.role IN ('coach','teacher') ORDER BY u.role, u.created_at;`
  );
  res.render("admin", { user: req.user, active: "admin", cohorts, coaches, flash: null, error: null });
});

app.get("/admin/cohort/:id", requireRole("admin"), async (req, res) => {
  const { rows: cohortRows } = await q(
    `SELECT co.*, u.display_name AS teacher_name
     FROM listen21_cohorts co
     LEFT JOIN listen21_users u ON u.id = co.coach_id
     WHERE co.id=$1;`,
    [req.params.id]
  );
  const cohort = cohortRows[0];
  if (!cohort) return res.status(404).send("找不到這個期別");

  const { rows: commitments } = await q(
    `SELECT c.id, c.child_name, c.created_at, u.real_name AS parent_name, u.display_name AS parent_nickname,
            (SELECT COUNT(*) FROM listen21_checkins ci WHERE ci.commitment_id=c.id)::int AS done_count
     FROM listen21_commitments c JOIN listen21_users u ON u.id = c.parent_id
     WHERE u.cohort_id=$1 ORDER BY c.created_at DESC;`,
    [cohort.id]
  );
  cohort.commitments = commitments.map((c) => {
    const nowDay = computeDay(c.created_at);
    const expected = Math.min(Math.max(nowDay - 1, 0), TOTAL_DAYS);
    return { ...c, stalled: c.done_count < expected };
  });

  const { rows: notStarted } = await q(
    `SELECT u.id, u.real_name, u.display_name, u.email, u.created_at
     FROM listen21_users u
     WHERE u.cohort_id=$1 AND u.role='parent'
       AND NOT EXISTS (SELECT 1 FROM listen21_commitments c WHERE c.parent_id = u.id)
     ORDER BY u.created_at DESC;`,
    [cohort.id]
  );
  cohort.notStarted = notStarted;

  res.render("admin-cohort", { user: req.user, active: "admin", cohort });
});

app.post("/admin/cohort", requireRole("admin"), async (req, res) => {
  const name = (req.body.name || "").trim();
  if (name) {
    await q("INSERT INTO listen21_cohorts (name, join_code) VALUES ($1,$2)", [name, genJoinCode()]);
  }
  res.redirect("/admin");
});

app.post("/admin/coach", requireRole("admin"), async (req, res) => {
  const display_name = (req.body.display_name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  const cohort_id = req.body.cohort_id || null;
  const role = req.body.role === "teacher" ? "teacher" : "coach";

  if (!display_name || !email || password.length < 6) {
    return res.redirect("/admin");
  }

  const password_hash = await bcrypt.hash(password, 10);
  const { rows } = await q(
    `INSERT INTO listen21_users (email, password_hash, role, display_name, real_name, wall_nickname)
     VALUES ($1,$2,$3,$4,$4,$5) RETURNING id;`,
    [email, password_hash, role, display_name, randomNickname()]
  );

  if (cohort_id) {
    await q("UPDATE listen21_cohorts SET coach_id=$1 WHERE id=$2", [rows[0].id, cohort_id]);
  }

  res.redirect("/admin");
});

app.post("/admin/coach/:id/delete", requireRole("admin"), async (req, res) => {
  const targetId = req.params.id;
  const { rows } = await q("SELECT id, role FROM listen21_users WHERE id=$1", [targetId]);
  const target = rows[0];
  // only ever allow deleting coach/teacher staff accounts through this route —
  // never admin or parent accounts, even if someone tampers with the form.
  if (!target || (target.role !== "coach" && target.role !== "teacher")) {
    return res.redirect("/admin");
  }

  await q("UPDATE listen21_cohorts SET coach_id=NULL WHERE coach_id=$1", [targetId]);
  await q("DELETE FROM listen21_likes WHERE user_id=$1", [targetId]);
  await q("DELETE FROM listen21_replies WHERE user_id=$1", [targetId]);
  await q("DELETE FROM listen21_users WHERE id=$1", [targetId]);

  res.redirect("/admin");
});

// ---------- boot ----------
async function start() {
  await migrate();
  const adminEmail = (process.env.ADMIN_EMAIL || "admin@listen21.local").toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || "changeme123";
  const adminPasswordHash = await bcrypt.hash(adminPassword, 10);
  await seed({ adminEmail, adminPasswordHash });

  app.listen(PORT, () => {
    console.log("listen21 server running on port " + PORT);
  });
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
