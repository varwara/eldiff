from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, flash, Response, g, abort
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import gzip
import logging
from logging.handlers import RotatingFileHandler

from typing import Union, Tuple, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        RotatingFileHandler("eldiff.log", maxBytes=1_000_000, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("ELDIFF_SECRET", "change_this!")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("ELDIFF_DB", os.path.join(BASE_DIR, "data", "updates.db"))

def get_db_connection():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        row = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return User(row["id"], row["username"]) if row else None

    @staticmethod
    def validate_login(username, password):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        
        logger = logging.getLogger(__name__)
        
        if row:
            try:
                # Log the actual row data
                logger.debug(f"User found: ID={row[0]}, Username={row[1]}")
                logger.debug(f"Stored hash type: {type(row[2])}, value: {row[2]}")
                
                stored_hash = row[2]
                result = check_password_hash(stored_hash, password)
                logger.debug(f"Password check result: {result}")
                
                if result:
                    return User(row[0], row[1])
            except Exception as e:
                logger.exception("Error during password validation")
        else:
            logger.warning(f"User not found: {username}")
            
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit   = SubmitField("Login")

@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.validate_login(form.username.data, form.password.data)
        if user:
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)

@app.route("/")
@login_required
def index():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT DISTINCT KbDate FROM updates ORDER BY KbDate DESC LIMIT 10"
    ).fetchall()
    dates = [r["KbDate"] for r in rows]
    return render_template("index_min.html", kbdates=dates)

@app.route("/get_vulnerabilities/<kbdate>")
@login_required
def get_vulnerabilities(kbdate):
    conn = get_db_connection()
    rows = conn.execute(
        """SELECT CVE,CWE,Impact,Severity,Tag AS Component,FAQ,URL AS FixURL,
                  FixedBuild,Exploit_Status 
           FROM Vulnerabilities 
          WHERE KbDate=?""", (kbdate,)
    ).fetchall()
    out = []
    for r in rows:
        st = { kv.split(":")[0]:kv.split(":")[1]
               for kv in r["Exploit_Status"].split(";") if ":" in kv }
        out.append({
            "CVE": r["CVE"],
            "CWE": r["CWE"],
            "Impact": r["Impact"],
            "Severity": r["Severity"],
            "Component": r["Component"],
            "FAQ": r["FAQ"],
            "FixURL": r["FixURL"],
            "FixedBuild": r["FixedBuild"],
            "Exploit_Status": {
                "Publicly Disclosed": st.get("Publicly Disclosed","N/A"),
                "Exploited": st.get("Exploited","N/A")
            }
        })
    return jsonify(out)

@app.route("/binaries")
@login_required
def binaries_page():
    kb = request.args.get("kbdate") or request.args.get("kb_date")
    if not kb: abort(400)
    return render_template("binaries_min.html", kbdate=kb)

@app.route("/get_binaries")
@login_required
def get_binaries():
    kb = request.args.get("kbdate") or request.args.get("kb_date")
    conn = get_db_connection()
    rows = conn.execute(
        """SELECT DISTINCT binary_name, binary_version, status, KB, binary_hash
             FROM binaries WHERE KbDate = ? ORDER BY binary_name""",
        (kb,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/functions")
@login_required
def functions_page():
    name = request.args.get("binary_name")
    ver  = request.args.get("binary_version")
    if not name or not ver: abort(400)
    return render_template("functions_min.html",
                           binary_name=name, binary_version=ver)

@app.route("/get_functions")
@login_required
def get_functions():
    name = request.args.get("binary_name")
    ver  = request.args.get("binary_version")
    conn = get_db_connection()
    # patched (functions table)
    patched = conn.execute(
      "SELECT ID, name1, address1, name2, address2, similarity "
      "FROM functions WHERE binary_name=? AND binary_version=?",
      (name, ver)
    ).fetchall()
    # added/deleted
    added = conn.execute(
      "SELECT id, name, address, function_type FROM added_deleted_funcs "
      "WHERE binary_name=? AND binary_version=?",
      (name, ver)
    ).fetchall()
    conn.close()

    out = []
    for r in patched:
        out.append({
          "ID": r["ID"],
          "type": "patched",
          "name1": r["name1"],
          "address1": r["address1"],
          "name2": r["name2"],
          "address2": r["address2"],
          "similarity": r["similarity"]
        })
    for r in added:
        t = "added" if r["function_type"] & 1 else "deleted"
        out.append({
          "ID": r["id"],
          "type": t,
          "name1": r["name"] if t=="deleted" else "",
          "address1": r["address"] if t=="deleted" else None,
          "name2": r["name"] if t=="added"   else "",
          "address2": r["address"] if t=="added"   else None,
          "similarity": None
        })
    return jsonify(out)

@app.route("/get_diff/<int:fid>")
@login_required
def get_diff(fid):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT diff FROM functions WHERE ID = ?", (fid,)
    ).fetchone()
    conn.close()
    if not row or not row["diff"]:
        return jsonify(success=False, error="No diff"), 404
    diff = gzip.decompress(row["diff"]).decode(errors="ignore")
    return jsonify(success=True, diff=diff)

@app.route("/get_func_blob/<int:fid>")
@login_required
def get_func_blob(fid):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT func_blob FROM added_deleted_funcs WHERE id = ?", (fid,)
    ).fetchone()
    conn.close()
    if not row or not row["func_blob"]:
        return jsonify(success=False, error="No code"), 404
    code = gzip.decompress(row["func_blob"]).decode(errors="ignore")
    return jsonify(success=True, code=code)

@app.route("/get_updates")
@login_required
def get_updates():
    conn = get_db_connection()
    updates = conn.execute("SELECT * FROM updates ORDER BY KbDate DESC LIMIT 10").fetchall()
    conn.close()
    return jsonify([dict(update) for update in updates])

@app.route("/get_latest_update")
@login_required
def get_latest_update():
    conn = get_db_connection()
    latest_update = conn.execute(
        "SELECT KbDate FROM updates ORDER BY CurrentReleaseDate DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if latest_update:
        return jsonify({"latest_update_id": latest_update["KbDate"]})
    else:
        return jsonify({"error": "No updates found"}), 404

@app.route("/get_component_mappings")
@login_required
def get_component_mappings():
    """
    Returns JSON array of { component, binary_name } from component_mapping table.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT component, binary_name FROM component_mapping")
        rows = cursor.fetchall()
        conn.close()
        return jsonify([{"component": r["component"], "binary_name": r["binary_name"]} for r in rows])
    except Exception as e:
        logger.error("Error fetching component mappings: %s", e)
        return jsonify({"error": "Database error"}), 500

@app.route("/get_all_functions")
@login_required
def get_all_functions():
    binary_name    = request.args.get("binary_name")
    binary_version = request.args.get("binary_version")
    if not binary_name or not binary_version:
        return jsonify({"error": "Missing required parameters"}), 400

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1) Patched
    patched_rows = cur.execute("""
      SELECT ID, name1, address1, name2, address2, similarity
        FROM functions
       WHERE binary_name    = ?
         AND binary_version = ?
       ORDER BY similarity DESC
    """, (binary_name, binary_version)).fetchall()

    # 2) ADDED  (bit 1 set: 1 or 1|4=5)
    added_rows = cur.execute("""
      SELECT id, name, address
        FROM added_deleted_funcs
       WHERE binary_name    = ?
         AND binary_version = ?
         AND (function_type & 1) != 0
    """, (binary_name, binary_version)).fetchall()

    # 3) DELETED (bit 2 set: 2 or 2|4=6)
    deleted_rows = cur.execute("""
      SELECT id, name, address
        FROM added_deleted_funcs
       WHERE binary_name    = ?
         AND binary_version = ?
         AND (function_type & 2) != 0
    """, (binary_name, binary_version)).fetchall()

    conn.close()

    funcs = []

    # patched
    for r in patched_rows:
        funcs.append({
          "ID":         r["ID"],
          "type":       "patched",
          "name1":      r["name1"],
          "address1":   to_u64_hex(r["address1"]),
          "name2":      r["name2"],
          "address2":   to_u64_hex(r["address2"]),
          "similarity": r["similarity"]
        })

    # added
    for r in added_rows:
        funcs.append({
          "ID":         r["id"],
          "type":       "added",
          "name1":      "",
          "address1":   None,
          "name2":      r["name"],
          "address2":   to_u64_hex(r["address"]),
          "similarity": None
        })

    # deleted
    for r in deleted_rows:
        funcs.append({
          "ID":         r["id"],
          "type":       "deleted",
          "name1":      r["name"],
          "address1":   to_u64_hex(r["address"]),
          "name2":      "",
          "address2":   None,
          "similarity": None
        })

    return jsonify({
      "patched": len(patched_rows),
      "added":   len(added_rows),
      "deleted": len(deleted_rows),
      "functions": funcs
    })

def to_u64_hex(val: Union[int,str]) -> str:
    raw = int(val, 16) if isinstance(val, str) and val.lower().startswith("0x") else int(val)
    u64 = raw & 0xFFFFFFFFFFFFFFFF
    return f"0x{u64:016x}"

def fetch_component_binary_cves(kb_date: str, conn):
    cur = conn.cursor()

    cur.execute("""
      SELECT
        cm.component,
        cm.binary_name,
        GROUP_CONCAT(v.CVE, ', ') AS cves
      FROM Vulnerabilities v
      JOIN component_mapping cm
        ON v.Tag = cm.component
      JOIN binaries b
        ON cm.binary_name    = b.binary_name
       AND b.KbDate          = v.KbDate
      WHERE v.KbDate = ?
      GROUP BY cm.component, cm.binary_name
      ORDER BY cm.component, cm.binary_name
    """, (kb_date,))

    rows = cur.fetchall()
    return [dict(r) for r in rows]

def fetch_high_risk_vulns(kb_date: str, conn):
    cur = conn.cursor()

    cur.execute("""
      SELECT 
        CVE,
        CWE,
        Severity,
        Exploit_Status,
        Tag AS component
      FROM Vulnerabilities
      WHERE KbDate = ?
        AND (
          Severity   IN ('Critical','Important')
          OR Exploit_Status LIKE '%Exploited:Yes%'
          OR Exploit_Status LIKE '%Publicly Disclosed:Yes%'
        )
      ORDER BY
        CASE WHEN Exploit_Status LIKE '%Exploited:Yes%' THEN 0 ELSE 1 END,
        CASE WHEN Exploit_Status LIKE '%Publicly Disclosed:Yes%' THEN 0 ELSE 1 END,
        CASE Severity
          WHEN 'Critical'  THEN 0
          WHEN 'Important' THEN 1
          WHEN 'Moderate'  THEN 2
          ELSE 3
        END,
        CVE LIMIT 8
    """, (kb_date,))

    rows = []
    for r in cur.fetchall():
        status_raw = r["Exploit_Status"]
        status = {kv.split(":")[0].strip(): kv.split(":")[1].strip()
                  for kv in status_raw.split(";") if ":" in kv}
        rows.append({
            "CVE": r["CVE"],
            "CWE": r["CWE"],
            "Severity": r["Severity"],
            # explicitly pass both flags
            "publicly_disclosed": status.get("Publicly Disclosed", "No"),
            "exploited":          status.get("Exploited", "No"),
            "component":          r["component"],
        })

    return rows

@app.route('/report/<kb_date>')
@login_required
def generate_report(kb_date):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    comp_bin_cves = fetch_component_binary_cves(kb_date, conn)
    high_risk     = fetch_high_risk_vulns(kb_date, conn)

    cur.execute("""
        SELECT CWE, COUNT(*) AS cnt
          FROM Vulnerabilities
         WHERE KbDate = ?
         GROUP BY CWE
         ORDER BY cnt DESC
         LIMIT 10
    """, (kb_date,))
    cwes = cur.fetchall()

    cur.execute("""
        SELECT binary_name, binary_version
         FROM binaries
         WHERE KbDate = ?
         ORDER BY binary_name
    """, (kb_date,))
    binaries = cur.fetchall()

    funcs = []
    for b in binaries:
        name    = b["binary_name"]
        version = b["binary_version"]

        cur.execute("""
            SELECT COUNT(*) AS patched 
              FROM functions
             WHERE binary_name    = ?
               AND binary_version = ?
        """, (name, version))
        total = cur.fetchone()["patched"]

        cur.execute("""
            SELECT COUNT(*) AS added
              FROM added_deleted_funcs
             WHERE binary_name    = ?
               AND binary_version = ?
               AND function_type  = 1
        """, (name, version))
        added = cur.fetchone()["added"]

        cur.execute("""
            SELECT COUNT(*) AS deleted
              FROM added_deleted_funcs
             WHERE binary_name    = ?
               AND binary_version = ?
               AND function_type  = 2
        """, (name, version))
        deleted = cur.fetchone()["deleted"]

        funcs.append({
            "binary_name":      name,
            "binary_version":   version,
            "total_functions":  total,
            "added_functions":  added,
            "deleted_functions": deleted
        })
    conn.close()

    return render_template(
        "report.html",
        kb_date       = kb_date,
        cwes          = cwes,
        funcs         = funcs, 
        comp_bin_cves = comp_bin_cves,
        high_risk     = high_risk
    )

@app.route("/get_binaries_for_component")
@login_required
def get_binaries_for_component():
    component = request.args.get("component")
    kb_date   = request.args.get("kb_date")
    if not component or not kb_date:
        return jsonify({"error": "Missing parameters"}), 400

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT b.binary_name, b.binary_version
          FROM component_mapping cm
          JOIN binaries b 
            ON cm.binary_name = b.binary_name
         WHERE cm.component = ?
           AND b.KbDate    = ?
        ORDER BY b.binary_name
    """, (component, kb_date))
    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {"binary_name": r["binary_name"],
         "binary_version": r["binary_version"]}
        for r in rows
    ])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
