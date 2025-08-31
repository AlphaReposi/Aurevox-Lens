import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
from flask_socketio import SocketIO, emit
import urllib.parse
import requests
import os
import time
import re
import json
import logging
import traceback
from threading import Lock
from dotenv import load_dotenv
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()  
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "fallback-dev-key")
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# Constants
SAVE_DIR = "collected"
DATA_FILE = "data.json"
BIN_ID = '68b33ccb43b1c97be93119ec'  # Replace with your JSON bin ID
SECRET_KEY = '$2a$10$rcJymoNUyCZ8j2uVTer40.s6xbsF8afkGgRuAr8U5yAcM2arGnjBO'  # Replace with your JSON bin master key
GUMROAD_PRODUCT_ID = '5ldD5GrO69z9HuDNM0jG_A=='
SCRAPEDO_TOKEN = '6787010ab6634fe0889a43a776c0de54c1f2d7dfd41' #using arevoxlens@gmail.com

# JSONBin API URL
BASE_URL = f'https://api.jsonbin.io/v3/b/{BIN_ID}'

EMAIL_DOMAINS = [
    "@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@aol.com",
    "@gmail.co.uk", "@yahoo.co.uk", "@hotmail.co.uk", "@outlook.co.uk", "@aol.co.uk"
]
PORTALS = [
    'instagram.com', 'linkedin.com', 'twitter.com', 'facebook.com',
    'pinterest.com', 'youtube.com', 'reddit.com', 'tiktok.com'
]

os.makedirs(SAVE_DIR, exist_ok=True)
data_lock = Lock()

# ------------------ JSONBin API Helper Functions ------------------

# JSONBin headers with master key
headers = {
    'Content-Type': 'application/json',
    'X-Master-Key': SECRET_KEY
}

# Fetch data from JSONBin
def load_data():
    try:
        logger.info("Loading data from JSONBin...")
        response = requests.get(BASE_URL, headers=headers, timeout=10)
        logger.debug(f"JSONBin response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            logger.debug(f"Raw JSONBin response type: {type(data)}")
            
            # Handle nested 'record' structure
            while isinstance(data, dict) and 'record' in data:
                data = data['record']
                logger.debug(f"Extracted record, new type: {type(data)}")
            
            logger.info(f"Successfully loaded {len(data) if isinstance(data, list) else 'unknown'} records")
            return data if isinstance(data, list) else []
        else:
            logger.error(f"Failed to load data from JSONBin: {response.status_code}")
            return []
    except Exception as e:
        logger.error(f"Exception in load_data: {str(e)}")
        logger.error(traceback.format_exc())
        return []

# Save data to JSONBin
def save_data_to_jsonbin(data):
    try:
        logger.info(f"Saving {len(data) if isinstance(data, list) else 'unknown'} records to JSONBin...")
        payload = {"record": data}
        response = requests.put(BASE_URL, headers=headers, json=payload, timeout=10)
        logger.debug(f"Save response status: {response.status_code}")
        
        if response.status_code == 200:
            logger.info("Successfully saved data to JSONBin")
            return True
        else:
            logger.error(f"Failed to save data: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Exception in save_data_to_jsonbin: {str(e)}")
        logger.error(traceback.format_exc())
        return False

# ------------------ Gumroad License Verification ------------------

def verify_gumroad_license(key):
    try:
        logger.info(f"Verifying Gumroad license for key: {key[:10]}...")
        r = requests.post('https://api.gumroad.com/v2/licenses/verify', 
                         data={'product_id': GUMROAD_PRODUCT_ID, 'license_key': key},
                         timeout=10)
        
        response_data = r.json()
        logger.debug(f"Gumroad response: {response_data}")
        
        if response_data.get('success'):
            logger.info(f"Gumroad license verification successful for key: {key[:10]}...")
            return True
        else:
            logger.warning(f"Gumroad license verification failed for key: {key[:10]}...")
            return False
    except Exception as e:
        logger.error(f"Exception in verify_gumroad_license: {str(e)}")
        return False

def add_key_to_database(key):
    try:
        logger.info(f"Adding new Gumroad key to database: {key[:10]}...")
        data = load_data()
        
        if not isinstance(data, list):
            data = []
        
        # Create new entry with default values
        new_entry = {
            "key": key,
            "username": f"gumroad_user_{key[:8]}",
            "credit": 1000,  # Default credits for new Gumroad users
            "expiration_date": None,  # No expiration for Gumroad users
            "scrapedo_token": SCRAPEDO_TOKEN,  # Default token
            "source": "gumroad"
        }
        
        data.append(new_entry)
        success = save_data_to_jsonbin(data)
        
        if success:
            logger.info(f"Successfully added Gumroad key to database: {key[:10]}...")
        else:
            logger.error(f"Failed to add Gumroad key to database: {key[:10]}...")
            
        return success
    except Exception as e:
        logger.error(f"Exception in add_key_to_database: {str(e)}")
        logger.error(traceback.format_exc())
        return False

# ------------------ Key Validation Helper ------------------

def validate_api_key(key):
    """
    Validates an API key and returns user data if valid.
    Returns tuple: (is_valid, user_data, error_message)
    """
    try:
        if not key:
            return False, None, "No API key provided"
            
        logger.debug(f"Validating key: {key[:10]}...")
        
        # First check if key exists in database
        entry = get_key_entry(key)

        # If not found in database, try Gumroad verification
        if not entry:
            logger.info(f"Key not found in database, checking Gumroad: {key[:10]}...")
            if verify_gumroad_license(key):
                # Add key to database
                if add_key_to_database(key):
                    # Try to get the entry again
                    entry = get_key_entry(key)
                    if not entry:
                        return False, None, "Authentication failed"
                else:
                    return False, None, "Authentication failed"
            else:
                return False, None, "Invalid API key"

        # Check expiration
        exp = entry.get("expiration_date")
        expired = False
        formatted_exp = "No Expiration Date"

        if exp:
            try:
                exp_date = datetime.strptime(exp, "%d-%m-%Y")
                formatted_exp = exp_date.strftime("%d %B %Y")
                if datetime.now() > exp_date:
                    expired = True
                    return False, None, f"API key expired on {formatted_exp}"
            except Exception as date_error:
                logger.error(f"Date parsing error for key {key[:10]}...: {str(date_error)}")
                return False, None, "Invalid expiration date format"

        user_data = {
            "valid": True,
            "username": entry.get("username"),
            "credit": int(entry.get("credit", 0)),
            "expiration_date": formatted_exp,
            "expired": expired,
            "scrapedo_token": entry.get("scrapedo_token")
        }
        
        logger.info(f"Key validation successful for user: {user_data['username']} (credits: {user_data['credit']})")
        return True, user_data, None
        
    except Exception as e:
        logger.error(f"Exception in validate_api_key: {str(e)}")
        logger.error(traceback.format_exc())
        return False, None, "Authentication failed"

# ------------------ Local Key Handling ------------------

def get_key_entry(key):
    try:
        logger.debug(f"Looking up key: {key[:10]}...")
        data = load_data()
        
        if not isinstance(data, list):
            logger.error(f"Data is not a list: {type(data)}")
            return None
            
        for entry in data:
            if not isinstance(entry, dict):
                logger.warning(f"Entry is not a dict: {type(entry)}")
                continue
                
            if entry.get("key") == key:
                logger.info(f"Found key entry for user: {entry.get('username', 'Unknown')}")
                return entry
        
        logger.warning(f"Key not found: {key[:10]}...")
        return None
    except Exception as e:
        logger.error(f"Exception in get_key_entry: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def update_key_credit(key, amount_to_subtract):
    try:
        logger.info(f"Updating credit for key {key[:10]}... - subtracting {amount_to_subtract}")
        data = load_data()
        
        if not isinstance(data, list):
            logger.error(f"Cannot update credits - data is not a list: {type(data)}")
            return False
            
        for entry in data:
            if not isinstance(entry, dict):
                logger.warning(f"Skipping non-dict entry: {type(entry)}")
                continue
                
            if entry.get("key") == key:
                old_credit = entry.get("credit", 0)
                entry["credit"] = max(0, old_credit - amount_to_subtract)
                logger.info(f"Updated credit from {old_credit} to {entry['credit']}")
                success = save_data_to_jsonbin(data)
                if success:
                    logger.info("Credit update saved successfully")
                else:
                    logger.error("Failed to save credit update")
                return success
        
        logger.warning(f"Key not found for credit update: {key[:10]}...")
        return False
    except Exception as e:
        logger.error(f"Exception in update_key_credit: {str(e)}")
        logger.error(traceback.format_exc())
        return False

# ------------------ Search Logic ------------------

def format_google_search_url(query):
    try:
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://www.google.com/search?q={encoded_query}&num=100"
        logger.debug(f"Generated search URL: {url}")
        return url
    except Exception as e:
        logger.error(f"Exception in format_google_search_url: {str(e)}")
        raise

def get_data_v2(url, token):
    try:
        logger.debug(f"Scraping URL: {url[:100]}...")
        cl = requests.session()
        target_url = urllib.parse.quote(url)
        wrapped_url = f"http://api.scrape.do/?token={token}&url={target_url}"
        
        logger.debug(f"Using scrape.do URL: {wrapped_url[:100]}...")
        response = cl.get(wrapped_url, timeout=30)
        logger.debug(f"Scrape.do response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Scrape.do returned status {response.status_code}")
        
        return response
    except Exception as e:
        logger.error(f"Exception in get_data_v2: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def extract_emails(html_text):
    try:
        logger.debug("Extracting emails from HTML content...")
        email_pattern = r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b'
        results = []
        
        if not html_text:
            logger.warning("Empty HTML content provided")
            return results
            
        soup = BeautifulSoup(html_text, 'html.parser')
        search_results = soup.find_all('div', class_='MjjYud')
        logger.debug(f"Found {len(search_results)} search result divs")
        
        for idx, result in enumerate(search_results):
            try:
                link = result.find('a', href=True)
                if not link:
                    logger.debug(f"Result {idx}: No link found")
                    continue
                    
                source_url = link['href']
                parsed_url = urlparse(source_url)
                
                if parsed_url.netloc.endswith('google.com'):
                    logger.debug(f"Result {idx}: Skipping Google URL")
                    continue
                
                snippet = result.find('div', class_='VwiC3b')
                if not snippet:
                    logger.debug(f"Result {idx}: No snippet found")
                    continue
                
                snippet_text = snippet.get_text()
                logger.debug(f"Result {idx}: Snippet length: {len(snippet_text)}")
                
                for email_match in re.finditer(email_pattern, snippet_text):
                    email = email_match.group().strip('.')
                    
                    # Filter out obviously fake emails
                    email_user = email.split('@')[0].lower()
                    if email_user in ['x22', '22', '2522']:
                        logger.debug(f"Filtering out fake email: {email}")
                        continue
                    
                    result_data = {
                        'email': email,
                        'source': source_url
                    }
                    results.append(result_data)
                    logger.debug(f"Found email: {email} from {source_url}")
                    
            except Exception as e:
                logger.error(f"Error processing search result {idx}: {str(e)}")
                continue
        
        # Remove duplicates
        seen = set()
        unique_results = []
        for r in results:
            key = (r['email'], r['source'])
            if key not in seen:
                seen.add(key)
                unique_results.append(r)
        
        logger.info(f"Extracted {len(unique_results)} unique emails from {len(results)} total matches")
        return unique_results
        
    except Exception as e:
        logger.error(f"Exception in extract_emails: {str(e)}")
        logger.error(traceback.format_exc())
        return []

def filter_facebook_pages(email_list):
    try:
        logger.debug(f"Filtering {len(email_list)} emails for Facebook pages...")
        filtered_results = []
        page_pattern = r'^https?://(?:www\.|m\.)?facebook\.com/[^/]+/?$'
        
        for item in email_list:
            source_url = item['source']
            
            if re.match(page_pattern, source_url):
                filtered_results.append(item)
                logger.debug(f"Added Facebook page: {source_url}")
            elif '/about/' in source_url:
                base_url = re.sub(r'/about/.*', '', source_url)
                filtered_item = {
                    'email': item['email'],
                    'source': base_url
                }
                filtered_results.append(filtered_item)
                logger.debug(f"Added Facebook about page: {base_url}")
        
        # Remove duplicates by URL
        unique_results = []
        seen_urls = set()
        for item in filtered_results:
            if item['source'] not in seen_urls:
                seen_urls.add(item['source'])
                unique_results.append(item)
        
        logger.info(f"Filtered to {len(unique_results)} unique Facebook pages")
        return unique_results
        
    except Exception as e:
        logger.error(f"Exception in filter_facebook_pages: {str(e)}")
        logger.error(traceback.format_exc())
        return email_list

def extract_info(html_content):
    try:
        logger.debug("Extracting Facebook page info...")
        soup = BeautifulSoup(html_content, 'html.parser')
        full_text = soup.get_text(separator='\n')
        
        def safe_find(prop):
            try:
                tag = soup.find('meta', {'property': prop}) or soup.find('meta', {'name': prop})
                return tag['content'].strip() if tag and 'content' in tag.attrs else None
            except:
                return None
        
        def match_line(lines, regex, exclude=None):
            for line in lines:
                if re.search(regex, line, re.IGNORECASE):
                    if exclude and re.search(exclude, line, re.IGNORECASE):
                        continue
                    return line.strip()
            return None
        
        # Extract intro block
        try:
            match = re.search(r'Intro\s+(.*?)\s+(?=\d{1,3}% recommend|\n\n|Related Pages|Page transparency|Photos)', full_text, re.DOTALL)
            intro_block = match.group(1).strip() if match else ''
        except:
            intro_block = ''
        
        intro_lines = [line.strip() for line in intro_block.split('\n') if line.strip()]
        logger.debug(f"Found {len(intro_lines)} intro lines")
        
        data = {}
        data['name'] = safe_find('og:title')
        data['image'] = safe_find('og:image')
        data['intro_description'] = intro_lines[0] if len(intro_lines) > 0 else None
        data['intro_categories'] = intro_lines[1] if len(intro_lines) > 1 else None
        data['intro_address'] = match_line(intro_lines, r'(United Kingdom|^\d{1,4}.+?,.+?)')
        data['intro_email'] = match_line(intro_lines, r'@')
        data['intro_phone'] = match_line(intro_lines, r'\+?\d[\d\s\-()]{7,}')
        data['intro_website'] = None
        
        # Extract website info
        try:
            icon = soup.find('img', src="https://static.xx.fbcdn.net/rsrc.php/v4/y3/r/BQdeC67wT9z.png")
            if icon:
                parent = icon.find_parent()
                if parent:
                    website_span = parent.find_next('span', attrs={'dir': 'auto'})
                    if website_span:
                        text = website_span.get_text(strip=True)
                        if text and '.' in text and '@' not in text:
                            data['intro_website'] = text
        except Exception as e:
            logger.debug(f"Website extraction error: {str(e)}")
            data['intro_website'] = None
        
        logger.info(f"Extracted Facebook page info: {data.get('name', 'Unknown')}")
        return data
        
    except Exception as e:
        logger.error(f"Exception in extract_info: {str(e)}")
        logger.error(traceback.format_exc())
        return {}

def get_facebook_page_data(fb_url):
    try:
        logger.info(f"Getting Facebook page data for: {fb_url}")
        token = '06323a5daf6443fd8d6adeda0fa328b8352cf3ccd1a'
        encoded_url = urllib.parse.quote(fb_url)
        scrape_url = f'https://api.scrape.do/?url={encoded_url}&token={token}&render=true&waitUntil=networkidle0&blockResources=false'
        
        logger.debug(f"Facebook scrape URL: {scrape_url[:100]}...")
        r = requests.get(scrape_url, timeout=30)
        logger.debug(f"Facebook scrape response status: {r.status_code}")
        
        if r.status_code != 200:
            logger.error(f"Facebook scrape failed: {r.status_code}")
            raise Exception(f"Scraping failed with status {r.status_code}")
        
        result = extract_info(r.text)
        logger.info(f"Successfully extracted Facebook data for: {result.get('name', 'Unknown')}")
        return result
        
    except Exception as e:
        logger.error(f"Exception in get_facebook_page_data: {str(e)}")
        logger.error(traceback.format_exc())
        raise

# ------------------ Routes ------------------

@app.route("/")
def index():
    """
    Main route that handles both authentication page and direct URL access.
    If 'key' parameter is provided in URL, validates it and redirects to collection page.
    """
    try:
        logger.info("Index route accessed")
        
        # Check if API key is provided as URL parameter
        api_key = request.args.get('key')
        
        if api_key:
            logger.info(f"Direct access attempted with URL key: {api_key[:10]}...")
            
            # Validate the API key
            is_valid, user_data, error_message = validate_api_key(api_key)
            
            if is_valid:
                logger.info(f"URL key validation successful for user: {user_data['username']}")
                # Redirect to collection page with key as parameter
                return redirect(url_for('collection', key=api_key))
            else:
                logger.warning(f"URL key validation failed: {error_message}")
                # Redirect to main page with error message
                return render_template("index.html", 
                                     portals=PORTALS, 
                                     domains=EMAIL_DOMAINS,
                                     error_message=f"Authentication failed: {error_message}")
        
        # Normal access - show authentication page
        logger.info("Normal access - serving authentication page")
        return render_template("index.html", portals=PORTALS, domains=EMAIL_DOMAINS)
        
    except Exception as e:
        logger.error(f"Exception in index route: {str(e)}")
        logger.error(traceback.format_exc())
        return render_template("index.html", 
                             portals=PORTALS, 
                             domains=EMAIL_DOMAINS,
                             error_message="An error occurred. Please try again.")

@app.route("/collection")
def collection():
    """
    Collection page that requires a valid API key as URL parameter.
    """
    try:
        logger.info("Collection page accessed")
        
        # Get API key from URL parameter
        api_key = request.args.get('key')
        
        if not api_key:
            logger.warning("Collection page accessed without API key - redirecting to main page")
            return redirect(url_for('index'))
        
        # Validate the API key
        is_valid, user_data, error_message = validate_api_key(api_key)
        
        if not is_valid:
            logger.warning(f"Invalid key used to access collection page: {error_message}")
            return redirect(url_for('index'))
        
        logger.info(f"Collection page access granted for user: {user_data['username']}")
        
        # Render collection page with user data and pre-filled key
        return render_template("collection.html", 
                             portals=PORTALS, 
                             domains=EMAIL_DOMAINS,
                             user_data=user_data,
                             api_key=api_key)
        
    except Exception as e:
        logger.error(f"Exception in collection route: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(url_for('index'))

@app.route("/download/<filename>")
def download(filename):
    try:
        logger.info(f"Download requested for file: {filename}")
        return send_from_directory(SAVE_DIR, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Download error for {filename}: {str(e)}")
        return "File not found", 404

from copy import deepcopy
@app.route("/check_key", methods=["POST"])
def check_key():
    try:
        logger.info("API key check requested")
        data = request.get_json()
        
        if not data:
            logger.error("No JSON data provided")
            return jsonify({"valid": False, "error": "No data provided"}), 400
            
        key = data.get("key")
        if not key:
            logger.error("No key provided in request")
            return jsonify({"valid": False, "error": "No key provided"}), 400
            
        # Use the new validation helper
        is_valid, user_data, error_message = validate_api_key(key)
        
        if is_valid:
            user_data_cpy = deepcopy(user_data)
            user_data_cpy.pop('scrapedo_token')
            return jsonify(user_data_cpy)
        else:
            return jsonify({"valid": False, "error": error_message})
        
    except Exception as e:
        logger.error(f"Exception in check_key: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"valid": False, "error": "Authentication failed"}), 500

@app.route("/lookup_facebook", methods=["POST"])
def lookup_facebook():
    try:
        logger.info("Facebook lookup requested")
        data = request.get_json()
        
        if not data:
            logger.error("No JSON data provided for Facebook lookup")
            return jsonify({"error": "Invalid request"}), 400
            
        url = data.get("url")
        if not url:
            logger.error("No URL provided for Facebook lookup")
            return jsonify({"error": "URL is required"}), 400
        
        logger.debug(f"Looking up Facebook URL: {url}")
        page_data = get_facebook_page_data(url)
        logger.info("Facebook lookup completed successfully")
        return jsonify(page_data)
        
    except Exception as e:
        logger.error(f"Exception in lookup_facebook: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Facebook lookup failed"}), 500

@socketio.on("start_collection")
def handle_start_collection(data):
    try:
        logger.info("=== STARTING EMAIL COLLECTION ===")
        logger.info(f"Received data keys: {list(data.keys()) if data else 'None'}")
        
        # Validate input data
        required_fields = ["search_for", "location", "sites", "domains", "key"]
        for field in required_fields:
            if field not in data:
                error_msg = "Missing required information"
                logger.error(f"Missing required field: {field}")
                emit("error", {"message": error_msg})
                return
        
        search_for = data["search_for"]
        location = data["location"]
        sites = data["sites"]
        domains = data["domains"]
        custom_domain = data.get("custom_domain", "").strip()
        key = data["key"]
        
        # Add custom domain to domains list if provided
        if custom_domain:
            if not custom_domain.startswith("@"):
                custom_domain = "@" + custom_domain
            domains.append(custom_domain)
            logger.info(f"Added custom domain: {custom_domain}")
        
        logger.info(f"Search params - Business: '{search_for}', Location: '{location}'")
        logger.info(f"Sites: {sites}")
        logger.info(f"Domains: {domains}")
        
        # Validate key
        entry = get_key_entry(key)
        if not entry:
            error_msg = "Invalid API key"
            logger.error(error_msg)
            emit("error", {"message": error_msg})
            return
        
        user_credits = entry.get("credit", 0)
        user_token = entry.get("scrapedo_token")
        username = entry.get("username", "Unknown")
        
        logger.info(f"User: {username}, Credits: {user_credits}")

        if not user_token:
            error_msg = "Authentication error"
            logger.error("No valid SD token found for this key")
            emit("error", {"message": error_msg})
            return

        # Calculate cost
        cost = len(sites) * len(domains) * 10
        logger.info(f"Calculated cost: {cost} credits ({len(sites)} sites × {len(domains)} domains × 10)")

        if user_credits < cost:
            error_msg = f"Insufficient credits. Need {cost}, have {user_credits}"
            logger.error(error_msg)
            emit("error", {"message": error_msg})
            return

        # Deduct credits immediately
        if not update_key_credit(key, cost):
            error_msg = "Failed to update credits"
            logger.error(error_msg)
            emit("error", {"message": error_msg})
            return

        logger.info(f"Credits deducted successfully. Starting collection...")

        collected = []
        facebook_emails = []
        total_queries = len(sites) * len(domains)
        query_count = 0

        for site_idx, site in enumerate(sites):
            for domain_idx, domain in enumerate(domains):
                try:
                    query_count += 1
                    query = f'site:{site} "{search_for}" "{domain}" "{location}"'
                    logger.info(f"Query {query_count}/{total_queries}: {query}")
                    
                    # Get search results
                    search_url = format_google_search_url(query)
                    res = get_data_v2(search_url, token=user_token)
                    
                    if res.status_code == 200:
                        logger.debug(f"Search successful, extracting emails...")
                        found = extract_emails(res.text)
                        logger.info(f"Found {len(found)} emails for query")
                        
                        for item in found:
                            if domain in item['email'] and item not in collected:
                                collected.append(item)
                                
                                is_facebook = 'facebook.com' in item['source']
                                if is_facebook:
                                    facebook_emails.append(item)
                                
                                logger.debug(f"New email: {item['email']} from {item['source']}")
                                
                                emit("new_email", {
                                    "email": item['email'],
                                    "source": item['source'],
                                    "is_facebook": is_facebook
                                })
                        
                        emit("update_count", {"count": len(collected)})
                        logger.info(f"Total collected so far: {len(collected)} emails")
                    else:
                        logger.error(f"Search failed with status: {res.status_code}")
                        
                except Exception as query_error:
                    logger.error(f"Error in query {query_count}: {str(query_error)}")
                    logger.error(traceback.format_exc())
                    continue
                
                # Rate limiting
                time.sleep(2)

        logger.info(f"=== COLLECTION COMPLETED ===")
        logger.info(f"Total emails collected: {len(collected)}")
        logger.info(f"Facebook emails: {len(facebook_emails)}")

        # Save results to file
        filename = f"{search_for.replace(' ', '_')}_{len(collected)}.txt"
        full_path = os.path.join(SAVE_DIR, filename)
        
        try:
            with open(full_path, "w", encoding="utf-8") as f:
                for item in collected:
                    f.write(f"{item['email']}\n")
            logger.info(f"Results saved to: {filename}")
        except Exception as save_error:
            logger.error(f"Failed to save results: {str(save_error)}")

        emit("done", {"download_url": f"/download/{filename}"})
        logger.info("Collection process completed successfully")
        
    except Exception as e:
        logger.error(f"CRITICAL ERROR in handle_start_collection: {str(e)}")
        logger.error(traceback.format_exc())
        emit("error", {"message": "Collection failed. Please try again."})

# ------------------ Error Handlers ------------------
@app.route('/assets/<path:filename>')
def serve_static(filename):
    return send_from_directory('assets', filename)

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    logger.error(traceback.format_exc())
    return jsonify({"error": "An error occurred"}), 500

@socketio.on_error()
def error_handler(e):
    logger.error(f"SocketIO error: {str(e)}")
    logger.error(traceback.format_exc())

# ------------------ Run ------------------

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
