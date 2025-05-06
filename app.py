import os
import csv
import io
import json
import time
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.utils import secure_filename
import stripe
import re

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///serpscraper.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "sk_test_...")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_...")
YOUR_DOMAIN = os.environ.get("YOUR_DOMAIN", "http://localhost:5000")

OXYLABS_USER = os.environ.get("OXYLABS_USER", "")
OXYLABS_PASS = os.environ.get("OXYLABS_PASS", "")
TEMP_RESULT_DIR = "results/tmp"

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/dashboard')
@login_required
def dashboard():
    jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.created_at.desc()).all()
    return render_template('dashboard.html', user=current_user, jobs=jobs)

# (Parsing and merge_and_rank_results functions go here in full, as in your original)
def parse_google_html(html, keyword):
    soup = BeautifulSoup(html, "lxml")
    results = []
    blocks = []

    # --- Ads (Top and Bottom) ---
    ads_rows = []
    for ad in soup.select('div[data-text-ad="1"], div[data-text-ad]'):
        title = ad.select_one('h3')
        title = title.get_text(strip=True) if title else ""
        link = ""
        for a in ad.find_all('a', href=True):
            if a['href'].startswith('http'):
                link = a['href']
                break
        display_link_tag = ad.find('span', string=lambda t: t and ("www." in t or ".com" in t or ".ca" in t))
        display_link = display_link_tag.get_text(strip=True) if display_link_tag else ""
        snippet = ""
        for span in ad.find_all('span'):
            text = span.get_text(strip=True)
            if text and text != title and "Ad" not in text:
                snippet = text
                break
        domain = extract_domain(link)
        brand = extract_brand(domain)
        row = {
            "keyword": keyword,
            "result_type": "ad",
            "title": title,
            "url": link,
            "display_link": display_link,
            "domain": domain,
            "brand": brand,
            "snippet": snippet,
            "question": "",
            "page": 1,
            "pos_overall": "",
            "pos": "",
        }
        if title and link:
            ads_rows.append(row)
    if ads_rows:
        blocks.append(("ad", ads_rows))

    # --- Organic Results ---
    organic_rows = []
    for res in soup.select('div.g, div.tF2Cxc'):
        title_tag = res.select_one('h3')
        title = title_tag.get_text(strip=True) if title_tag else ""
        a_tag = res.select_one('a[href]')
        url = a_tag['href'] if a_tag else ""
        snippet_tag = res.select_one('.VwiC3b, .IsZvec, span.st')
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
        domain = extract_domain(url)
        brand = extract_brand(domain)
        row = {
            "keyword": keyword,
            "result_type": "organic",
            "title": title,
            "url": url,
            "display_link": domain,
            "domain": domain,
            "brand": brand,
            "snippet": snippet,
            "question": "",
            "page": 1,
            "pos_overall": "",
            "pos": "",
        }
        if title and url:
            organic_rows.append(row)
    if organic_rows:
        blocks.append(("organic", organic_rows))

    # --- People Also Ask (PAA) ---
    paa_rows = []
    for paa in soup.select('div.related-question-pair, .Wt5Tfe, .iDjcJe, .y8AWGd'):
        question = paa.get_text(strip=True)
        row = {
            "keyword": keyword,
            "result_type": "paa",
            "title": "",
            "url": "",
            "display_link": "",
            "domain": "",
            "brand": "",
            "snippet": "",
            "question": question,
            "page": 1,
            "pos_overall": "",
            "pos": "",
        }
        if question:
            paa_rows.append(row)
    if paa_rows:
        blocks.append(("paa", paa_rows))

    # --- AI Overview (SGE) block, if present as a special summary ---
    aio_rows = []
    aio_box = soup.find(lambda tag: tag.name == "div" and ("AI Overview" in tag.text or "Here's a more detailed breakdown:" in tag.text))
    if aio_box:
        aio_text = aio_box.get_text(separator="\n", strip=True)
        row = {
            "keyword": keyword,
            "result_type": "ai_overview",
            "title": "",
            "url": "",
            "display_link": "",
            "domain": "",
            "brand": "",
            "snippet": aio_text,
            "question": "",
            "page": 1,
            "pos_overall": "",
            "pos": "",
        }
        aio_rows.append(row)
    if aio_rows:
        blocks.append(("ai_overview", aio_rows))

    # --- Assign positions ---
    results = []
    abs_pos = 1
    organic_pos = 1
    ad_pos = 1
    for block_type, rows_in_block in blocks:
        block_abs_pos = abs_pos
        for idx, row in enumerate(rows_in_block):
            row["absolute_position"] = block_abs_pos
            if block_type == "organic":
                row["organic_position"] = organic_pos
                organic_pos += 1
            else:
                row["organic_position"] = ""
            if block_type == "ad":
                row["ad_position"] = ad_pos
                ad_pos += 1
            else:
                row["ad_position"] = ""
            row["serp_block_position"] = idx + 1
            results.append(row)
        abs_pos += 1

    results.sort(key=lambda r: r["absolute_position"])
    return results

def merge_and_rank_results(results):
    seen_urls = set()
    deduped = []
    for row in results:
        url = (row.get("url") or "").lower()
        if not url:
            key = f"{row.get('result_type')}|{row.get('snippet','')[:50]}|{row.get('question','')[:50]}"
        else:
            key = url
        if key not in seen_urls:
            seen_urls.add(key)
            deduped.append(row)
    aio = [r for r in deduped if r['result_type'] == 'ai_overview']
    ads = [r for r in deduped if r['result_type'] == 'ad']
    organic = [r for r in deduped if r['result_type'] == 'organic']
    others = [r for r in deduped if r['result_type'] not in ('ai_overview','ad','organic')]
    merged = aio + ads + organic + others
    abs_pos = 1
    organic_pos = 1
    for row in merged:
        row['absolute_position'] = abs_pos
        if row['result_type'] == 'organic':
            row['organic_position'] = organic_pos
            organic_pos += 1
        else:
            row['organic_position'] = ''
        abs_pos += 1
    return merged

@app.route('/new_job', methods=['GET', 'POST'])
@login_required
def new_job():
    # You can redirect to /scraper or render the new job page directly
    return redirect(url_for('scraper'))

@app.route('/scraper', methods=['GET', 'POST'])
@login_required
def scraper():
    search_engines = [
        ("google.ca", "google.ca (Canada)"),
        ("google.com", "google.com (US)"),
        ("google.co.uk", "google.co.uk (UK)"),
    ]
    user_agent_types = [
        ("desktop", "Desktop"),
        ("mobile", "Mobile"),
        ("tablet", "Tablet"),
    ]
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
        domain = request.form.get('search_engine', 'google.ca').replace('google.', '')
        hl = request.form.get('hl', 'en').strip()
        gl = request.form.get('gl', 'ca').strip()
        location = request.form.get('location', '')
        locale = f"{hl}-{gl}"

        sources = ["google_search", "google_ads"]
        credits_needed = len(keywords) * len(sources)
        if current_user.credits < credits_needed:
            flash(f"You need at least {credits_needed} credits to run this job.")
            return redirect(url_for('new_job'))

        results = []
        actual_credits_used = 0
        job_paused = False

        for keyword in keywords:
            for source in sources:
                payload = {
                    "source": source,
                    "domain": domain,
                    "geo_location": location,
                    "locale": locale,
                    "user_agent_type": user_agent_type,
                    "query": keyword,
                    "context": [
                        {"key": "results_language", "value": hl},
                        {"key": "filter", "value": 1}
                    ],
                }
                print(f"[Oxylabs Realtime Request] Payload for '{keyword}' ({source}):")
                print(json.dumps(payload, indent=2))
                try:
                    response = requests.post(
                        'https://realtime.oxylabs.io/v1/queries',
                        auth=(OXYLABS_USER, OXYLABS_PASS),
                        json=payload,
                        timeout=120
                    )
                    print(f"[Oxylabs HTTP Status] {response.status_code}")
                    resp_json = response.json()
                    print(f"[Oxylabs RAW RESPONSE]:\n{json.dumps(resp_json, indent=2)[:2000]}{'... [truncated]' if len(json.dumps(resp_json)) > 2000 else ''}")
                    found_structured = False
                    for res in resp_json.get("results", []):
                        page_num = res.get("page", 1)
                        content = res.get("content", {})
                        if isinstance(content, dict) and "results" in content:
                            found_structured = True
                            for block, items in content["results"].items():
                                if not isinstance(items, list) or not items:
                                    continue
                                for item in items:
                                    url_ = item.get("url") or item.get("link") or ""
                                    domain_ = extract_domain(url_)
                                    brand = extract_brand(domain_)
                                    row = {
                                        "keyword": keyword,
                                        "result_type": block,
                                        "title": item.get("title", ""),
                                        "url": url_,
                                        "domain": domain_,
                                        "brand": brand,
                                        "snippet": item.get("snippet", ""),
                                        "question": item.get("question", ""),
                                        "description": item.get("description", ""),
                                        "page": page_num,
                                        "pos_overall": item.get("pos_overall", item.get("pos", "")),
                                        "pos": item.get("pos", ""),
                                    }
                                    results.append(row)
                        elif isinstance(content, str):
                            print("[DEBUG] content is HTML, attempting fallback parsing.")
                            parsed_rows = parse_google_html(content, keyword)
                            if parsed_rows:
                                results.extend(parsed_rows)
                            else:
                                results.append({
                                    "keyword": keyword,
                                    "result_type": f"{source}_html_only",
                                    "title": "",
                                    "url": "",
                                    "domain": "",
                                    "brand": "",
                                    "snippet": "",
                                    "question": "",
                                    "description": "",
                                    "page": page_num,
                                    "pos_overall": "",
                                    "pos": ""
                                })
                    if not found_structured and not results:
                        results.append({
                            "keyword": keyword,
                            "result_type": f"{source}_no_data",
                            "title": "",
                            "url": "",
                            "domain": "",
                            "brand": "",
                            "snippet": "",
                            "question": "",
                            "description": "",
                            "page": "",
                            "pos_overall": "",
                            "pos": ""
                        })
                except Exception as e:
                    print(f"[Oxylabs ERROR] {e}")
                    flash(f"Error for keyword '{keyword}' ({source}): {e}")
                actual_credits_used += 1
                if current_user.credits < actual_credits_used:
                    job_paused = True
                    flash("You ran out of credits during this job. The job was paused.")
                    break

        current_user.credits -= actual_credits_used
        db.session.commit()

        results = merge_and_rank_results(results)

        fieldnames = [
            "keyword", "result_type", "title", "url", "domain", "brand", "snippet", "question",
            "page", "pos_overall", "pos",
            "absolute_position", "organic_position", "ad_position", "serp_block_position"
        ]

        filename = f"job_{current_user.id}_{secure_filename('_'.join(keywords[:3]))}_realtime.csv"
        filepath = os.path.join("results", filename)
        os.makedirs("results", exist_ok=True)
        with open(filepath, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for row in results:
                for field in fieldnames:
                    if field not in row:
                        row[field] = ""
                writer.writerow(row)

        job_status = "paused" if job_paused else "finished"
        job = Job(
            user_id=current_user.id,
            keywords=",".join(keywords[:10]) + ("..." if len(keywords) > 10 else ""),
            user_agent_type=user_agent_type,
            location=location,
            search_engine=domain,
            status=job_status,
            result_file=filename,
            credits_used=actual_credits_used
        )
        db.session.add(job)
        db.session.commit()

        flash(f"Job complete! {actual_credits_used} credits used. Download from dashboard.")
        return redirect(url_for('dashboard'))

    return render_template(
        'new_job.html',
        user=current_user,
        search_engines=search_engines,
        user_agent_types=user_agent_types
    )
@app.route('/results/<filename>')
@login_required
def download_result(filename):
    return send_from_directory('results', filename, as_attachment=True)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html', user=current_user)

@app.route('/download_template')
@login_required
def download_template():
    template_path = 'results/keyword_template.csv'
    if not os.path.exists('results'):
        os.makedirs('results')
    if not os.path.exists(template_path):
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write('keyword\nexample keyword 1\nexample keyword 2\n')
    return send_file(template_path, as_attachment=True)

@app.route('/import_example')
@login_required
def import_example():
    return redirect(url_for('download_template'))

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
@app.route('/create_payg_checkout', methods=['POST'])
@login_required
def create_payg_checkout():
    # Implement your PAYG Stripe logic here, or use a placeholder for now
    return "Pay As You Go checkout coming soon."

@app.route('/close_account', methods=['GET', 'POST'])
@login_required
def close_account():
    if request.method == 'POST':
        user = current_user
        logout_user()
        # Optionally: delete user's jobs
        Job.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("Your account has been closed and all data deleted.")
        return redirect(url_for('index'))
    return render_template('close_account.html')


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

@app.cli.command('init-db')
def init_db():
    db.create_all()
    print("Database initialized.")

if __name__ == "__main__":
    app.run(debug=True)
