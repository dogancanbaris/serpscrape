from flask import Flask, request, render_template, send_file
import requests as pyrequests
import csv
import io
from urllib.parse import urlparse

app = Flask(__name__)

VALUE_SERP_API_KEY = 'D48CA87BCD2A4386A55A8A442A04062F'

@app.route('/')
def home():
 return render_template('index.html')

def get_domain(url):
 try:
  netloc = urlparse(url).netloc
  if netloc.startswith('www.'):
   netloc = netloc[4:]
  return netloc.split('/')[0]
 except Exception:
  return ''

def flatten_results(keyword, location, language, serp_json, result_blocks):
 output_rows = []
 absolute_pos_counter = 1
 overall_pos_counter = 1
 organic_pos_counter = 1  # New: counts only organic results

 for result_type, json_key in result_blocks:
  block = serp_json.get(json_key)
  if not block:
   continue

  # Ads
  if result_type == 'ad' and isinstance(block, list):
   for ad in block:
    output_rows.append({
     'keyword': keyword,
     'location': location,
     'language': language,
     'result_type': 'ad',
     'absolute_position': absolute_pos_counter,
     'overall_position': overall_pos_counter,
     'organic_position': '',
     'url': ad.get('link', ''),
     'domain': get_domain(ad.get('link', '')),
     'title': ad.get('title', ''),
     'description': ad.get('snippet', '')
    })
    overall_pos_counter += 1
   absolute_pos_counter += 1

  # Answer Box / AIO
  elif result_type == 'aio':
   if isinstance(block, dict):
    links = []
    if 'link' in block:
     links.append({'link': block['link'], 'title': block.get('title', ''), 'description': block.get('snippet', '')})
    if 'list' in block and isinstance(block['list'], list):
     for item in block['list']:
      links.append({'link': item.get('link', ''), 'title': item.get('title', ''), 'description': item.get('snippet', '')})
    for lnk in links:
     output_rows.append({
      'keyword': keyword,
      'location': location,
      'language': language,
      'result_type': 'aio',
      'absolute_position': absolute_pos_counter,
      'overall_position': overall_pos_counter,
      'organic_position': '',
      'url': lnk.get('link', ''),
      'domain': get_domain(lnk.get('link', '')),
      'title': lnk.get('title', ''),
      'description': lnk.get('description', '')
     })
     overall_pos_counter += 1
    absolute_pos_counter += 1

  # People Also Ask (PPA)
  elif result_type == 'ppa' and isinstance(block, list):
   for ppa in block:
    output_rows.append({
     'keyword': keyword,
     'location': location,
     'language': language,
     'result_type': 'ppa',
     'absolute_position': absolute_pos_counter,
     'overall_position': overall_pos_counter,
     'organic_position': '',
     'url': '',  # Usually no direct link for PPA
     'domain': '',
     'title': ppa.get('question', ''),
     'description': ppa.get('snippet', '')
    })
    overall_pos_counter += 1
   absolute_pos_counter += 1

  # Organic Results
  elif result_type == 'organic' and isinstance(block, list):
   for org in block:
    output_rows.append({
     'keyword': keyword,
     'location': location,
     'language': language,
     'result_type': 'organic',
     'absolute_position': absolute_pos_counter,
     'overall_position': overall_pos_counter,
     'organic_position': organic_pos_counter,
     'url': org.get('link', ''),
     'domain': get_domain(org.get('link', '')),
     'title': org.get('title', ''),
     'description': org.get('snippet', '')
    })
    overall_pos_counter += 1
    organic_pos_counter += 1
   absolute_pos_counter += 1

  # Local Map Pack
  elif result_type == 'local_map' and isinstance(block, dict) and 'places' in block:
   for place in block['places']:
    output_rows.append({
     'keyword': keyword,
     'location': location,
     'language': language,
     'result_type': 'local_map',
     'absolute_position': absolute_pos_counter,
     'overall_position': overall_pos_counter,
     'organic_position': '',
     'url': place.get('website', ''),
     'domain': get_domain(place.get('website', '')),
     'title': place.get('title', ''),
     'description': place.get('address', '')
    })
    overall_pos_counter += 1
   absolute_pos_counter += 1

  # Videos
  elif result_type == 'videos' and isinstance(block, list):
   for vid in block:
    output_rows.append({
     'keyword': keyword,
     'location': location,
     'language': language,
     'result_type': 'videos',
     'absolute_position': absolute_pos_counter,
     'overall_position': overall_pos_counter,
     'organic_position': '',
     'url': vid.get('link', ''),
     'domain': get_domain(vid.get('link', '')),
     'title': vid.get('title', ''),
     'description': vid.get('channel', '')
    })
    overall_pos_counter += 1
   absolute_pos_counter += 1

  # Social (Twitter)
  elif result_type == 'social' and isinstance(block, list):
   for soc in block:
    output_rows.append({
     'keyword': keyword,
     'location': location,
     'language': language,
     'result_type': 'social',
     'absolute_position': absolute_pos_counter,
     'overall_position': overall_pos_counter,
     'organic_position': '',
     'url': soc.get('link', ''),
     'domain': get_domain(soc.get('link', '')),
     'title': soc.get('title', ''),
     'description': soc.get('snippet', '')
    })
    overall_pos_counter += 1
   absolute_pos_counter += 1

 return output_rows

@app.route('/search', methods=['POST'])
def search():
 data = request.json
 search_engine = data.get('search_engine', 'google.com')
 device = data.get('device', 'desktop')
 location = data.get('location', '')
 page_depth = int(data.get('page_depth', 10))
 keywords = data.get('keywords', [])
 language = 'en'  # You can add a language field to your form if needed
 include_aio = data.get('include_aio', True)
 include_ads = data.get('include_ads', True)

 # Build result_blocks based on toggles
 result_blocks = []
 if include_ads:
  result_blocks.append(('ad', 'ads'))
 if include_aio:
  result_blocks.append(('aio', 'answer_box'))
 # Always include these
 result_blocks += [
  ('ppa', 'people_also_ask'),
  ('organic', 'organic_results'),
  ('local_map', 'local_results'),
  ('videos', 'videos'),
  ('social', 'twitter_results'),
 ]

 all_rows = []

 for query in keywords:
  params = {
    'api_key': VALUE_SERP_API_KEY,
    'q': query,
    'location': location,
    'num': page_depth,
    'device': device,
    'domain': search_engine
  }
  try:
   response = pyrequests.get('https://api.valueserp.com/search', params=params)
   response.raise_for_status()
   result_json = response.json()
   rows = flatten_results(query, location, language, result_json, result_blocks)
   all_rows.extend(rows)
  except Exception as e:
   all_rows.append({
     'keyword': query,
     'location': location,
     'language': language,
     'result_type': 'error',
     'absolute_position': '',
     'overall_position': '',
     'organic_position': '',
     'url': '',
     'domain': '',
     'title': '',
     'description': str(e)
   })

 # Prepare CSV in memory
 output = io.StringIO()
 writer = csv.DictWriter(output, fieldnames=[
  'keyword', 'location', 'language', 'result_type', 'absolute_position',
  'overall_position', 'organic_position', 'url', 'domain', 'title', 'description'
 ])
 writer.writeheader()
 for row in all_rows:
  writer.writerow(row)

 output.seek(0)
 return send_file(
  io.BytesIO(output.getvalue().encode()),
  mimetype='text/csv',
  as_attachment=True,
  download_name='serpient_results.csv'
 )

if __name__ == '__main__':
 app.run(host='127.0.0.1', port=5000, debug=True)