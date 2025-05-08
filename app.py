import os
import csv
import io
from flask import send_file
import json
import time
import requests
from urllib.parse import urlparse
from flask import send_file, redirect
from google.cloud import storage
from tempfile import NamedTemporaryFile
from bs4 import BeautifulSoup
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.utils import secure_filename
import stripe

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GCS_BUCKET_NAME = os.environ.get('GCS_BUCKET_NAME')  # set this in your Render env vars

# For Render: store credentials JSON in env var, use from_service_account_info
credentials_json = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS_JSON')
if credentials_json:
    from google.oauth2 import service_account
    credentials = service_account.Credentials.from_service_account_info(json.loads(credentials_json))
    gcs_client = storage.Client(credentials=credentials)
else:
    gcs_client = storage.Client()
gcs_bucket = gcs_client.bucket(GCS_BUCKET_NAME)

# ==== Config ====
app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///serpscraper.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Stripe
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]
YOUR_DOMAIN = os.environ["YOUR_DOMAIN"]

# ValueSERP
VALUE_SERP_API_KEY = os.environ["VALUE_SERP_API_KEY"]
VALUE_SERP_SEARCH_URL = "https://api.valueserp.com/search"
VALUE_SERP_BATCH_URL = "https://api.valueserp.com/batch"

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ==== Models ====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    plan = db.Column(db.String(32), default="Starter")
    credits = db.Column(db.Integer, default=0)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    @property
    def plan_total_credits(self):
        plan_credits = {
            "Starter": 30000,
            "Growth": 60000,
            "Pro": 120000,
            "Agency": 240000,
            "Enterprise": 1200000,
        }
        return plan_credits.get(self.plan, 0)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=db.func.now())
    keywords = db.Column(db.Text)
    user_agent_type = db.Column(db.String(32))
    location = db.Column(db.String(128))
    search_engine = db.Column(db.String(32))
    status = db.Column(db.String(32), default="finished")
    result_file = db.Column(db.String(256))
    credits_used = db.Column(db.Integer, default=0)
    batch_id = db.Column(db.String(128), nullable=True)  # for batch jobs
    mode = db.Column(db.String(16), default="realtime")  # 'realtime' or 'batch'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==== Utility Functions ====
def extract_domain(url):
    try:
        if not url:
            return ""
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""

def extract_brand(domain):
    if not domain:
        return ""
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-2].capitalize()
    return domain.capitalize()

def calculate_credits(include_ads, include_aio):
    # 1 credit: organic only
    # 2 credits: ads OR aio
    # 3 credits: both
    if include_ads and include_aio:
        return 3
    elif include_ads or include_aio:
        return 2
    else:
        return 1
        
def upload_to_gcs(local_path, gcs_filename):
    blob = gcs_bucket.blob(gcs_filename)
    blob.upload_from_filename(local_path)
    print(f"Uploaded {local_path} to gs://{GCS_BUCKET_NAME}/{gcs_filename}")

def get_signed_url(gcs_filename, expiration=3600):
    blob = gcs_bucket.blob(gcs_filename)
    return blob.generate_signed_url(expiration=expiration)

        
@app.route('/download_batch/<int:job_id>')
@login_required
def download_batch(job_id):
    import pprint

    job = Job.query.get_or_404(job_id)
    if job.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for('dashboard'))

    # Path to the batch results JSON file (you should save this after batch completes)
    result_json_path = os.path.join("results", f"{job.batch_id}.json")
    if not os.path.exists(result_json_path):
        flash("Batch results are not ready yet. Please try again later.", "warning")
        return redirect(url_for('dashboard'))

    with open(result_json_path, "r", encoding="utf-8") as f:
        batch_results = json.load(f)

    fieldnames = [
        "keyword", "result_type", "title", "url", "domain", "brand", "snippet", "question",
        "page", "absolute_position", "organic_position", "ad_position", "serp_block_position"
    ]

    def parse_valueserp_response(resp_json, keyword):
        rows = []
        ads_found = False
        aio_found = False

        # --- Organic Results ---
        for pos, item in enumerate(resp_json.get("organic_results", []), 1):
            rows.append({
                "keyword": keyword,
                "result_type": "organic",
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "domain": extract_domain(item.get("link", "")),
                "brand": extract_brand(extract_domain(item.get("link", ""))),
                "snippet": item.get("snippet", ""),
                "question": "",
                "page": 1,
                "absolute_position": pos,
                "organic_position": pos,
                "ad_position": "",
                "serp_block_position": "",
            })

        # --- Ads ---
        for pos, item in enumerate(resp_json.get("ads", []), 1):
            ads_found = True
            rows.append({
                "keyword": keyword,
                "result_type": "ad",
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "domain": extract_domain(item.get("link", "")),
                "brand": extract_brand(extract_domain(item.get("link", ""))),
                "snippet": item.get("description", ""),
                "question": "",
                "page": 1,
                "absolute_position": pos,
                "organic_position": "",
                "ad_position": pos,
                "serp_block_position": "",
            })

        # --- AI Overview (SGE) ---
        if resp_json.get("ai_overview"):
            aio_found = True
            rows.append({
                "keyword": keyword,
                "result_type": "ai_overview",
                "title": "",
                "url": "",
                "domain": "",
                "brand": "",
                "snippet": resp_json.get("ai_overview", ""),
                "question": "",
                "page": 1,
                "absolute_position": "",
                "organic_position": "",
                "ad_position": "",
                "serp_block_position": "",
            })

        # --- People Also Ask (PAA) ---
        for pos, item in enumerate(resp_json.get("people_also_ask", []), 1):
            rows.append({
                "keyword": keyword,
                "result_type": "paa",
                "title": "",
                "url": "",
                "domain": "",
                "brand": "",
                "snippet": "",
                "question": item.get("question", ""),
                "page": 1,
                "absolute_position": pos,
                "organic_position": "",
                "ad_position": "",
                "serp_block_position": "",
            })

        return rows, ads_found, aio_found

    results = []
    actual_credits_used = 0
    keywords_in_batch = [search.get("q", "") for search in batch_results.get("searches", [])]

    # Assume batch_results is a dict: { 'results': [ { 'keyword': ..., 'result': {...} }, ... ] }
    for item in batch_results.get("results", []):
        keyword = item.get("keyword", "")
        resp_json = item.get("result", {})
        parsed_rows, ads_found, aio_found = parse_valueserp_response(resp_json, keyword)
        results.extend(parsed_rows)
        used = 1
        if ads_found and aio_found:
            used = 3
        elif ads_found or aio_found:
            used = 2
        actual_credits_used += used

    # Refund unused credits
    credits_charged = job.credits_used
    unused_credits = credits_charged - actual_credits_used
    if unused_credits > 0:
        user = current_user
        user.credits += unused_credits
        db.session.commit()
        flash(f"Job finished! {actual_credits_used} credits used, {unused_credits} credits refunded.", "info")
    else:
        flash(f"Job finished! {actual_credits_used} credits used.", "info")

    # Write export CSV
    local_path = f"/tmp/{filename}"
    with open(local_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in results:
            for field in fieldnames:
                if field not in row:
                    row[field] = ""
            writer.writerow(row)

    # Update job as finished and set result file
    job.status = "finished"
    job.result_file = filename
    job.credits_used = actual_credits_used
    db.session.commit()

    return send_file(filepath, as_attachment=True)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.")
            return redirect(url_for('signup'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Signup successful!")
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for('index'))
    
@app.route('/')
def index():
    # Render a landing page, or redirect to login/signup
    return redirect(url_for('login'))
    # or: return render_template('index.html')

@app.route("/init-db")
def init_db_route():
    db.create_all()
    return "Database initialized!"


@app.route('/playground', methods=['GET', 'POST'])
@login_required
def playground():
    import pprint
    import logging

    result_html = None
    result_json = None
    result_csv = None
    error = None
    params = {}
    output_type = 'html'
    form_defaults = {
        'search_type': 'search',
        'q': '',
        'location': '',
        'gl': 'us',
        'hl': 'en',
        'google_domain': 'google.com',
        'device': 'desktop',
        'output': 'html',
        'include_ai_overview': 'true',
        'include_ads': 'true',
        'flatten_results': '',
        'filter': '',
        'sort_by': '',
        'time_period': '',
        'include_answer_box': '',
        'page': '1',
        'num': '10',
        'max_page': '',
        'cookie': '',
        'include_raw_html': '',
    }

    if request.method == 'POST':
        # Get all fields from the form
        params = {
            'api_key': VALUE_SERP_API_KEY,
            'q': request.form.get('q', ''),
            'location': request.form.get('location', ''),
            'gl': request.form.get('gl', 'us'),
            'hl': request.form.get('hl', 'en'),
            'google_domain': request.form.get('google_domain', 'google.com'),
            'device': request.form.get('device', 'desktop'),
            'output': request.form.get('output', 'html'),
            'include_ai_overview': request.form.get('include_ai_overview', 'true'),
            'include_ads': request.form.get('include_ads', 'true'),
            'flatten_results': request.form.get('flatten_results', ''),
            'filter': request.form.get('filter', ''),
            'sort_by': request.form.get('sort_by', ''),
            'time_period': request.form.get('time_period', ''),
            'include_answer_box': request.form.get('include_answer_box', ''),
            'page': request.form.get('page', '1'),
            'num': request.form.get('num', '10'),
            'max_page': request.form.get('max_page', ''),
            'cookie': request.form.get('cookie', ''),
            'include_raw_html': request.form.get('include_raw_html', ''),
        }
        # Only send non-empty values
        params = {k: v for k, v in params.items() if v not in [None, '', False]}

        # Only send search_type if not 'search'
        search_type = request.form.get('search_type', 'search')
        if search_type and search_type != 'search':
            params['search_type'] = search_type
        elif 'search_type' in params:
            del params['search_type']

        output_type = params.get('output', 'html')

        # LOGGING: Print the outgoing params
        print("="*40)
        print("Sending request to ValueSERP with params:")
        pprint.pprint(params)

        try:
            resp = requests.get(VALUE_SERP_SEARCH_URL, params=params)
            print("HTTP status code:", resp.status_code)
            print("Response headers:", dict(resp.headers))
            print("Raw response text (first 1000 chars):", resp.text[:1000])
            if output_type == 'html':
                result_html = resp.text
            elif output_type == 'json':
                result_json = resp.json()
            elif output_type == 'csv':
                result_csv = resp.text
        except Exception as e:
            error = str(e)
            logging.exception("Error during ValueSERP API request")
        # For sticky form: update defaults with submitted values
        form_defaults.update(request.form)
    else:
        params = form_defaults

    # LOGGING: Final data for debugging
    print("Playground output_type:", output_type)
    print("Error:", error)

    return render_template(
        'playground.html',
        params=params,
        result_html=result_html,
        result_json=result_json,
        result_csv=result_csv,
        output_type=output_type,
        error=error
    )


@app.route('/dashboard')
@login_required
def dashboard():
    jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).all()
    # Poll/update batch jobs that are not finished
    for job in jobs:
        if job.mode == "batch" and job.status not in ["finished", "failed"]:
            poll_and_update_batch_job(job)
    return render_template('dashboard.html', user=current_user, jobs=jobs)

@app.route('/new_job', methods=['GET', 'POST'])
@login_required
def new_job():
    # This route is an alias for /scraper for nav compatibility
    return redirect(url_for('scraper'))

@app.route('/scraper', methods=['GET', 'POST'])
@login_required
def scraper():
    import pprint
    search_engines = [
        ("google.com", "Google.com (United States)"),
        ("google.co.uk", "Google.co.uk (UK)"),
        ("google.ca", "Google.ca (Canada)"),
    ]
    user_agent_types = [
        ("desktop", "Desktop"),
        ("mobile", "Mobile"),
        ("tablet", "Tablet"),
    ]
    jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).all()

    def parse_valueserp_response(resp_json, keyword):
        rows = []
        abs_pos = 1

        # --- AI Overview (always position 1 if present) ---
        if resp_json.get("ai_overview"):
            rows.append({
                "keyword": keyword,
                "result_type": "ai_overview",
                "title": "",
                "url": "",
                "domain": "",
                "brand": "",
                "snippet": resp_json.get("ai_overview", ""),
                "question": "",
                "page": 1,
                "absolute_position": abs_pos,
                "organic_position": "",
            })
            abs_pos += 1

        # --- Ads (top) ---
        ads = resp_json.get("ads", [])
        for item in ads:
            rows.append({
                "keyword": keyword,
                "result_type": "ad",
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "domain": extract_domain(item.get("link", "")),
                "brand": extract_brand(extract_domain(item.get("link", ""))),
                "snippet": item.get("description", ""),
                "question": "",
                "page": 1,
                "absolute_position": abs_pos,
                "organic_position": "",
            })
            abs_pos += 1

        # --- Organic Results ---
        organic_pos = 1
        for item in resp_json.get("organic_results", []):
            rows.append({
                "keyword": keyword,
                "result_type": "organic",
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "domain": extract_domain(item.get("link", "")),
                "brand": extract_brand(extract_domain(item.get("link", ""))),
                "snippet": item.get("snippet", ""),
                "question": "",
                "page": 1,
                "absolute_position": abs_pos,
                "organic_position": organic_pos,
            })
            abs_pos += 1
            organic_pos += 1

        # --- PAA (People Also Ask), all share the same abs_pos ---
        paa = resp_json.get("people_also_ask", [])
        if paa:
            for item in paa:
                rows.append({
                    "keyword": keyword,
                    "result_type": "paa",
                    "title": "",
                    "url": "",
                    "domain": "",
                    "brand": "",
                    "snippet": "",
                    "question": item.get("question", ""),
                    "page": 1,
                    "absolute_position": abs_pos,
                    "organic_position": "",
                })
            abs_pos += 1

        # --- Local results, all share the same abs_pos ---
        locals = resp_json.get("local_results", [])
        if locals:
            for item in locals:
                rows.append({
                    "keyword": keyword,
                    "result_type": "local",
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "domain": extract_domain(item.get("link", "")),
                    "brand": extract_brand(extract_domain(item.get("link", ""))),
                    "snippet": item.get("description", ""),
                    "question": "",
                    "page": 1,
                    "absolute_position": abs_pos,
                    "organic_position": "",
                })
            abs_pos += 1

        # --- Shopping results, all share the same abs_pos ---
        shopping = resp_json.get("shopping_results", [])
        if shopping:
            for item in shopping:
                rows.append({
                    "keyword": keyword,
                    "result_type": "shopping",
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "domain": extract_domain(item.get("link", "")),
                    "brand": extract_brand(extract_domain(item.get("link", ""))),
                    "snippet": item.get("description", ""),
                    "question": "",
                    "page": 1,
                    "absolute_position": abs_pos,
                    "organic_position": "",
                })
            abs_pos += 1

        return rows

    if request.method == 'POST':
        keywords = []
        if 'csv_file' in request.files and request.files['csv_file'].filename:
            csv_file = request.files['csv_file']
            stream = io.StringIO(csv_file.stream.read().decode("UTF8"), newline=None)
            for row in csv.DictReader(stream):
                kw = row.get('keyword', '').strip()
                if kw:
                    keywords.append(kw)
        else:
            keywords = request.form.get('keywords', '').splitlines()
            keywords = [kw.strip() for kw in keywords if kw.strip()]

        user_agent_type = request.form.get('user_agent_type', 'desktop')
        search_engine = request.form.get('search_engine', 'google.com')
        location = request.form.get('location', '')
        hl = request.form.get('hl', 'en').strip()
        gl = request.form.get('gl', 'us').strip()
        page_depth = int(request.form.get('page_depth', 10))

        credits_per_keyword = 3
        credits_needed = len(keywords) * credits_per_keyword

        if current_user.credits < credits_needed:
            flash(f"You need at least {credits_needed} credits to run this job.")
            return redirect(url_for('scraper'))

        # Deduct credits up front
        current_user.credits -= credits_needed
        db.session.commit()

        all_results = []
        actual_credits_used = 0

        for keyword in keywords:
            params = {
                'api_key': VALUE_SERP_API_KEY,
                'q': keyword,
                'location': location,
                'gl': gl,
                'hl': hl,
                'device': user_agent_type,
                'num': page_depth,
                'include_ai_overview': 'true',
                'include_ads': 'true',
                'ads_optimized': 'true'
            }
            print("="*30)
            print("Sending GET to ValueSERP for:", keyword)
            pprint.pprint(params)
            resp = requests.get(VALUE_SERP_SEARCH_URL, params=params)
            try:
                resp_json = resp.json()
            except Exception:
                print("Could not decode JSON for keyword:", keyword)
                print("Raw response:", resp.text)
                continue

            rows = parse_valueserp_response(resp_json, keyword)
            all_results.extend(rows)

            # Determine credits used for this keyword
            ads_found = any(row["result_type"] == "ad" for row in rows)
            aio_found = any(row["result_type"] == "ai_overview" for row in rows)
            used = 1
            if ads_found and aio_found:
                used = 3
            elif ads_found or aio_found:
                used = 2
            actual_credits_used += used
            # Refund if less than 3 charged
            if used < credits_per_keyword:
                refund = credits_per_keyword - used
                current_user.credits += refund
                db.session.commit()

        # Write/export all_results to CSV
        fieldnames = [
            "keyword", "result_type", "title", "url", "domain", "brand", "snippet", "question",
            "page", "absolute_position", "organic_position"
        ]
        filename = f"job_{current_user.id}_{secure_filename('_'.join(keywords[:3]))}_valueserp.csv"
        local_path = f"/tmp/{filename}"  # Always use /tmp in cloud
        with open(local_path, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for row in all_results:
                for field in fieldnames:
                    if field not in row:
                        row[field] = ""
                writer.writerow(row)
        
        gcs_filename = f"results/user_{current_user.id}/{filename}"
        print(f"[GCS UPLOAD] About to upload {local_path} to {gcs_filename} in bucket {GCS_BUCKET_NAME}")
        upload_to_gcs(local_path, gcs_filename)
        print(f"[GCS UPLOAD] Upload complete for {gcs_filename}")

        job = Job(
            user_id=current_user.id,
            keywords=",".join(keywords[:10]) + ("..." if len(keywords) > 10 else ""),
            user_agent_type=user_agent_type,
            location=location,
            search_engine=search_engine,
            status="finished",
            result_file=gcs_filename,  # store GCS path!
            result_file=filename,
            credits_used=actual_credits_used,
            batch_id=None,
            mode="batch"
        )
        db.session.add(job)
        db.session.commit()
        flash(f"Job finished! {actual_credits_used} credits used, {credits_needed-actual_credits_used} credits refunded.", "info")
        return redirect(url_for('dashboard'))

    return render_template(
        'new_job.html',
        user=current_user,
        search_engines=search_engines,
        user_agent_types=user_agent_types
    )

@app.route('/results/<path:filename>')
@login_required
def download_result(filename):
    # filename is the GCS path stored in Job.result_file
    signed_url = get_signed_url(filename)
    return redirect(signed_url)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/download_batch_template')
@login_required
def download_batch_template():
    template_path = 'results/batch_job_template.csv'
    if not os.path.exists('results'):
        os.makedirs('results')
    # Always overwrite with the latest template and examples
    with open(template_path, 'w', encoding='utf-8') as f:
        f.write(
            'keyword,location,gl,hl,device,search_engine,page_depth,include_ai_overview,include_ads\n'
            'buy engagement ring,Toronto,ca,en,desktop,google.ca,10,true,true\n'
            'best pizza,New York,us,en,mobile,google.com,20,false,true\n'
            'laptop deals,London,uk,en,desktop,google.co.uk,10,true,false\n'
        )
    return send_file(template_path, as_attachment=True)


@app.route('/plan/success')
@login_required
def payment_success():
    return render_template('payment_success.html')

@app.route('/plan/cancel')
@login_required
def payment_cancel():
    flash("Payment was cancelled.")
    return redirect(url_for('payment'))

@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        print("Webhook signature error:", e)
        return "Invalid signature", 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_email = session.get('customer_email') or (session.get('customer_details') or {}).get('email')
        user = User.query.filter_by(email=customer_email).first()
        if not user:
            print(f"No user found for {customer_email}")
            return '', 200

        session_id = session.get('id')
        checkout_session = stripe.checkout.Session.retrieve(session_id, expand=['line_items'])
        price_id = None
        if hasattr(checkout_session, 'line_items') and checkout_session.line_items.data:
            price_id = checkout_session.line_items.data[0].price.id

        price_to_plan = {
            "price_1RJ2olE65Iw6zJEop7w2zV8U": ("Starter", 30000),
            "price_1RJ2n3E65Iw6zJEoLqeWEdaj": ("Growth", 60000),
            "price_1RJ2pIE65Iw6zJEoaU7iKqpm": ("Pro", 120000),
            "price_1RJ2pnE65Iw6zJEozf2Ywy9d": ("Agency", 240000),
            "price_1RJ2qME65Iw6zJEoHodzC0sX": ("Enterprise", 1200000),
        }
        if price_id in price_to_plan:
            plan_name, plan_credits = price_to_plan[price_id]
            user.plan = plan_name
            user.credits += plan_credits
            db.session.commit()
            print(f"User {user.email} upgraded to {user.plan} and now has {user.credits} credits.")
        else:
            name = ""
            if hasattr(checkout_session, 'line_items') and checkout_session.line_items.data:
                name = checkout_session.line_items.data[0].description or checkout_session.line_items.data[0].price.product
            match = re.search(r'Pay As You Go Credits \((\d+)\)', name)
            if match:
                credits = int(match.group(1))
                user.credits += credits
                db.session.commit()
                print(f"User {user.email} bought {credits} PAYG credits (total: {user.credits}).")
            else:
                print(f"Could not determine credits for user {user.email}")

    return '', 200

@app.route('/create_checkout_session', methods=['POST'])
@login_required
def create_checkout_session():
    price_id = request.form['stripe_price_id']
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=current_user.email,
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='payment',
            success_url=YOUR_DOMAIN + '/plan/success',
            cancel_url=YOUR_DOMAIN + '/plan/cancel',
        )
        return redirect(checkout_session.url)
    except Exception as e:
        flash(str(e))
        return redirect(url_for('payment'))

@app.route('/plan', methods=['GET'])
@login_required
def payment():
    plans = [
        {"name": "Starter", "credits": 30000, "price": 120, "stripe_price_id": "price_1RJ2olE65Iw6zJEop7w2zV8U"},
        {"name": "Growth",  "credits": 60000, "price": 210, "stripe_price_id": "price_1RJ2n3E65Iw6zJEoLqeWEdaj"},
        {"name": "Pro",     "credits": 120000, "price": 360, "stripe_price_id": "price_1RJ2pIE65Iw6zJEoaU7iKqpm"},
        {"name": "Agency",  "credits": 240000, "price": 660, "stripe_price_id": "price_1RJ2pnE65Iw6zJEozf2Ywy9d"},
        {"name": "Enterprise", "credits": 1200000, "price": 3000, "stripe_price_id": "price_1RJ2qME65Iw6zJEoHodzC0sX"},
    ]
    return render_template('payment.html', plans=plans, user=current_user if current_user.is_authenticated else None)

@app.route('/create_payg_checkout', methods=['POST'])
@login_required
def create_payg_checkout():
    credits = int(request.form['credits'])
    price = float(request.form['price'])
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=current_user.email,
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'Pay As You Go Credits ({credits})',
                    },
                    'unit_amount': int(price * 100),
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=YOUR_DOMAIN + '/plan/success',
            cancel_url=YOUR_DOMAIN + '/plan/cancel',
        )
        return redirect(checkout_session.url)
    except Exception as e:
        flash(str(e))
        return redirect(url_for('payment'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        if not current_user.check_password(current):
            flash("Current password is incorrect.")
            return redirect(url_for('change_password'))
        if new != confirm:
            flash("New passwords do not match.")
            return redirect(url_for('change_password'))
        if len(new) < 6:
            flash("New password must be at least 6 characters.")
            return redirect(url_for('change_password'))
        current_user.set_password(new)
        db.session.commit()
        flash("Password changed successfully!")
        return redirect(url_for('account'))
    return render_template('change_password.html')

@app.route('/close_account', methods=['GET', 'POST'])
@login_required
def close_account():
    if request.method == 'POST':
        user = current_user
        logout_user()
        Job.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("Your account has been closed and all data deleted.")
        return redirect(url_for('index'))
    return render_template('close_account.html')
    
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory('static', 'robots.txt')

def poll_and_update_batch_job(job):
    """Poll ValueSERP for batch results, update job status and save results if ready."""
    if not job.batch_id or job.status == "finished":
        return

    # 1. Call ValueSERP Batch Results Endpoint (adjust endpoint as needed)
    batch_results_url = f"https://api.valueserp.com/batch/{job.batch_id}/results"
    params = {"api_key": VALUE_SERP_API_KEY}
    resp = requests.get(batch_results_url, params=params)
    try:
        data = resp.json()
    except Exception:
        print("Failed to decode batch results JSON.")
        return

    # 2. Check if batch is ready (adjust this logic per ValueSERP docs)
    if data.get("status") == "completed" or data.get("status") == "finished":
        # Save JSON results to file
        result_json_path = os.path.join("results", f"{job.batch_id}.json")
        with open(result_json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        job.status = "ready"
        db.session.commit()
    elif data.get("status") in ["pending", "processing"]:
        job.status = data.get("status")
        db.session.commit()
    elif data.get("status") == "failed":
        job.status = "failed"
        db.session.commit()

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.cli.command('init-db')
def init_db():
    db.create_all()
    print("Database initialized.")

if __name__ == "__main__":
    app.run(debug=True)
