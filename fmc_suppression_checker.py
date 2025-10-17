import requests
import csv
from datetime import datetime
from getpass import getpass

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class FMC:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.headers, self.domain_id = self.get_auth_headers_and_domain()

    def get_auth_headers_and_domain(self):
        url = f"https://{self.host}/api/fmc_platform/v1/auth/generatetoken"
        r = requests.post(url, auth=(self.username, self.password), verify=False)
        r.raise_for_status()
        headers = {
            'X-auth-access-token': r.headers['X-auth-access-token'],
            'Content-Type': 'application/json'
        }
        return headers, r.headers['DOMAIN_UUID']

    def get_all_intrusion_rules(self, csv_writer):
        """Fetch all intrusion rules globally and dump suppression info as we go."""
        offset = 0
        limit = 200
        total_fetched = 0

        while True:
            url = f"https://{self.host}/api/fmc_config/v1/domain/{self.domain_id}/object/intrusionrules?offset={offset}&limit={limit}&expanded=true"
            r = requests.get(url, headers=self.headers, verify=False)
            r.raise_for_status()
            data = r.json()

            if 'items' not in data or not data['items']:
                break

            for rule in data['items']:
                rule_name = rule.get('name', 'Unknown')
                suppressed = 'True' if 'suppression' in rule else 'False'
                csv_writer.writerow([rule_name, suppressed])
                print(f"→ {rule_name} — Suppressed: {suppressed}")

            batch_count = len(data['items'])
            total_fetched += batch_count
            print(f"Fetched {batch_count} rules (Total: {total_fetched})")

            if batch_count < limit:
                break
            offset += limit


def main():
    host = input("Enter FMC host: ")
    username = input("Enter FMC username: ")
    password = getpass("Enter FMC password: ")

    fmc = FMC(host, username, password)
    print("Fetching all global intrusion rules and writing suppression status...")

    filename = f"global_intrusion_rules_suppression_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Rule Name (GID:SID)", "Suppressed"])
        fmc.get_all_intrusion_rules(writer)

    print(f"\n✅ Output written to {filename}")

if __name__ == "__main__":
    main()
