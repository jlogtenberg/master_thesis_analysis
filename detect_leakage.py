import os
import csv
import json
from tqdm import tqdm
import LeakDetector
from datetime import datetime
from urllib.parse import urlparse
import tldextract

MAX_LEAK_DETECTION_LAYERS = 3

def extract_domain(url):
	"""Extract the eTLD + 1 from a URL"""
	extract = tldextract.extract(url)
	return f"{extract.domain}.{extract.suffix}"

def extract_header_value(headers, name):
	"""Extract the values of a given header"""
	for header in headers:
		if header['name'].lower() == name.lower():
			return header['value']
	return None

def get_search_strings(general, profile, site):
	"""Creates the search strings for the LeakDetector, contains some mutations on the regular user data for more coverage"""
	search_strings = []
	
	# Exclude these categories from search strings, since these contain numbers that occur outside of leaks
	general_exclusions = ["date_of_birth", "credit_card_expiry_month", "credit_card_expiry_year", "credit_card_cvv", "email_prefix", "email_suffix"]
	profile_exclusions = ["payment_options", "house_number"]
	
	# Add email for specific site
	email_prefix = general.get("email_prefix", "")
	email_suffix = general.get("email_suffix", "")
	email_basic = f"{email_prefix}@{email_suffix}"
	email_variant = f"{email_prefix}+{site}@{email_suffix}"
	search_strings.append(email_basic)
	search_strings.append(email_variant)

	# Add full name to search strings (instead of only first and last name seperately)
	first_name = general.get("first_name", "")
	last_name = general.get("last_name", "")
	full_name = f"{first_name} {last_name}".strip()
	search_strings.append(full_name)

	# Add phone number with country code and with country code but without the '+' to search strings
	phone_number = profile.get("local_format")
	international_phone_number = profile.get("international_format")
	international_phone_number_stripped = international_phone_number[1:]
	search_strings.append(phone_number)
	search_strings.append(international_phone_number)
	search_strings.append(international_phone_number_stripped)

	country_code = profile.get("country_code")
	if country_code == "+31":
		zip_code = profile.get("zip_code", "")
		spaced_zip = f"{zip_code[:4]} {zip_code[4:]}"
		search_strings.append(spaced_zip)

	# Add full address to search strings (instead of only street and house number seperately)
	street = profile.get("street", "")
	house_number = profile.get("house_number", "")
	full_address = f"{street} {house_number}"
	search_strings.append(full_address)

	# Add expiration date to search strings (instead of only month and year seperately)
	credit_card_expiry_month = general.get("credit_card_expiry_month", "")
	credit_card_expiry_year = general.get("credit_card_expiry_year", "")
	expiry_date = f"{credit_card_expiry_month}/{credit_card_expiry_year}"
	search_strings.append(expiry_date)

	# Add credit card number without spaces to search strings
	credit_card_number = general.get("credit_card_number", "")
	cc_no_spaces = credit_card_number.replace(" ", "")
	search_strings.append(cc_no_spaces)

	# Add all of the information contained in the general and profile user data, with the exception of the keys contained in the exclusions
	for key, val in general.items():
		if key not in general_exclusions and isinstance(val, str):
			search_strings.append(val)

	for key, val in profile.items():
		if key not in profile_exclusions and isinstance(val, str):
			search_strings.append(val)
	return search_strings

def load_website_language_map(csv_file):
	"""Loads the website language mapping from the given CSV file"""
	site_country_map = {}
	with open(csv_file, "r", encoding="utf-8") as f:
		reader = csv.reader(f, delimiter=";")
		next(reader)
		for row in reader:
			if len(row) >= 2:
				site, country = row[0].strip(), row[1].strip().lower()
				site_country_map[site] = country
	return site_country_map

def initialize_leak_detector(search_strings):
	"""Initializes a new LeakDetector that will search for the specified search strings"""
	return LeakDetector.LeakDetector(
		search_strings,
		encoding_set=LeakDetector.LIKELY_ENCODINGS,
		hash_set=LeakDetector.LIKELY_HASHES,
		encoding_layers=MAX_LEAK_DETECTION_LAYERS,
		hash_layers=MAX_LEAK_DETECTION_LAYERS,
		debugging=False
	)

def record_leak(encoding_or_hash, method, leaked_value, timestamp):
	"""Returns a found leak in a set format"""
	return {
		"leaked_value": leaked_value, 
		"encoding_or_hash": encoding_or_hash,
		"leak_method": method,
		"timestamp": timestamp
	}

def check_field(field, content, method, timestamp):
	"""Checks the specified field in the entry for leaks using the leak detector"""
	leak_details = []
	if content:
		results = method(content)
		for result in results:
			if len(result) == 4:  # encoding, hash, hash, leaked_value
				encoding_or_hash_chain = "-".join(result[:-1])
				leaked_value = result[-1]
				leak_details.append(record_leak(encoding_or_hash_chain, field, leaked_value, timestamp))
			elif len(result) == 3:  # encoding or hash, encoding or hash, leaked_value
				encoding_or_hash_chain = "-".join(result[:-1])
				leaked_value = result[-1]
				leak_details.append(record_leak(encoding_or_hash_chain, field, leaked_value, timestamp))
			elif len(result) == 2:  # encoding or hash, leaked_value
				encoding_or_hash_chain = result[0]
				leaked_value = result[1]
				leak_details.append(record_leak(encoding_or_hash_chain, field, leaked_value, timestamp))
	return leak_details

def process_har_and_check_for_leaks(har_path, site, leak_detector):
	"""Searches for leaks in the specified HAR file"""
	leaks = {}

	# Open the HAR file
	with open(har_path, 'r', encoding='utf-8') as f:
		har = json.load(f)

	entries = har.get('log', {}).get('entries', [])

	# Goes over every request and response entry in the HAR file
	for entry in tqdm(entries, desc="Processing HAR entries", unit="entry"):

		# Get the timestamp of the request
		timestamp = entry.get('startedDateTime', datetime.utcnow().isoformat() + 'Z')

		# Get the request URL, and extract the domain name if possible. If the request contains a blob URL, deal with it accordingly
		entry_url = entry.get("request", {}).get("url")
		if entry_url:
			if entry_url.startswith("blob:"):
				entry_url_domain = "blob-url"
			else:
				entry_url_domain = extract_domain(entry_url)

		# Check for leaks in all the specified fields in the entry and add them to dictionary for the current entry
		all_leaks = []
		all_leaks.extend(check_field("url", entry.get("request", {}).get("url"), leak_detector.check_url, timestamp))
		all_leaks.extend(check_field("referrer", extract_header_value(entry.get("request", {}).get("headers", []), "Referer"), leak_detector.check_referrer_str, timestamp))
		all_leaks.extend(check_field("postData", entry.get("request", {}).get("postData", {}).get("text"), leak_detector.check_post_data, timestamp))
		all_leaks.extend(check_field("location", extract_header_value(entry.get("response", {}).get("headers", []), "Location"), leak_detector.check_location_header, timestamp))
		all_leaks.extend(check_field("setCookie", extract_header_value(entry.get("response", {}).get("headers", []), "Set-Cookie"), leak_detector.check_cookie_str, timestamp))

		# Check for leaks in the attached cookies
		for cookie in entry.get("cookies", []):
			cookie_str = f"{cookie.get('name')}={cookie.get('value')}"
			all_leaks.extend(check_field("Cookies", cookie_str, leak_detector.check_cookie_str, timestamp))

		# Add leaks found in the entry to dictionary for leaks in the entire HAR file
		if all_leaks:
			if entry_url_domain not in leaks:
				leaks[entry_url_domain] = []
			leaks[entry_url_domain].extend(all_leaks)
	return leaks

def process_all_hars_and_check_for_leaks(base_folder, site_country_map, leak_results_file, general, profiles):
	"""Searches for leaks in all the HAR files in the base folder"""

	final_results = []

	# Main loop that goes over every website in the base folder
	for site in os.listdir(base_folder):
		print(f"Checking {site} for leaks")
		site_path = os.path.join(base_folder, site)
		har_file = os.path.join(site_path, 'traffic.har')
		if os.path.isdir(site_path) and os.path.isfile(har_file):

			# Selects the correct country profile to ensure that the correct user data is being searched for
			country = site_country_map.get(site, "dutch")
			profile = profiles.get(country, {})

			# Create the search strings for this specific website and intialize leak_detector that checks for these search strings
			search_strings = get_search_strings(general, profile, site)
			leak_detector = initialize_leak_detector(search_strings)

			# Process the HAR file of the crawl on this website and check for leaks
			site_leaks = process_har_and_check_for_leaks(har_file, site, leak_detector)

			# If there are any leaks, add them to the final_results dictionary
			if site_leaks:
				# final_results.setdefault(site, {}).update(site_leaks)
				formatted_results = format_site_results(site, site_leaks)
				final_results.append(formatted_results)

	if final_results:
		with open(leak_results_file, "w", encoding="utf-8") as f:
			json.dump(final_results, f, indent=2)

def format_site_results(site, leaks):
    """Formats the leaks of a single site"""
    site_entry = {"website": site, "leaks": []}
    for domain, leak_list in leaks.items():
        leak_entry = {
            "domain": domain,
            "data_leaked": leak_list
        }
        site_entry["leaks"].append(leak_entry)
    return site_entry

def main():
	# Specify the base folder where the crawl file saved, the user_data_file where the user data is stored and the site_language_file where the links between websites and languages are stored.
	base_folder = 'semrush_accept/data'
	user_data_file = 'semrush_accept/user_data.json'
	site_language_file = 'websites_language_semrush.csv'
	leak_results_file = 'semrush_accept/leak_results.json'

	# Load the site_language mapping from the file
	site_language_map = load_website_language_map(site_language_file)
	with open(user_data_file, 'r', encoding='utf-8') as f:
		user_data = json.load(f)

	# Get the user general and language profiles from the file.
	general = user_data.get("general", {})
	profiles = user_data.get("profile", {})

	process_all_hars_and_check_for_leaks(base_folder, site_language_map, leak_results_file, general, profiles)

	print("Leak detection complete! Results saved to leak_results.json.")

if __name__ == '__main__':
	main()