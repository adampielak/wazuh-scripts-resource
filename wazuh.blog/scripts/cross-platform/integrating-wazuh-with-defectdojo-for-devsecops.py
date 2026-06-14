<!-- Source: https://wazuh.com/blog/integrating-wazuh-with-defectdojo-for-devsecops/ | Article: Integrating Wazuh with DefectDojo for DevSecOps -->
import requests
import json
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Replace these with your actual values
base_url = "https://<IP_ADDRESS>/api/v2"
products_url = f"{base_url}/products/"
findings_url = f"{base_url}/findings/"
api_key = "<API_KEY>"
headers = {"accept": "application/json", "Authorization": f"Token {api_key}"}

# This parameter sets the maximum number of findings you can fetch per request
params = {"active": "true", "limit": "1000"}

output_file = "/var/log/defectdojo.json"

def fetch_products():
    """
    Fetch products data and extract findings_list and name.
    """
    try:
        response = requests.get(products_url, headers=headers, verify=False)
        response.raise_for_status()
        json_data = response.json()
        # Extract findings_list and name for each product
        return [
            {
            "findings_list": product.get("findings_list", []),
            "name": product.get("name")
            }
            for product in json_data.get("results", [])
        ]
    except requests.exceptions.RequestException as e:
        print("Error fetching products:", e)
        return []

def fetch_findings():
    """
    Fetch findings data and extract only the required fields.
    """
    required_fields = [
    "id", "display_status", "title", "date", "cwe",
    "cvssv3_score", "url", "severity", "description",
    "impact", "references", "numerical_severity",
    "hash_code", "line", "file_path", "service"
    ]
    try:
        response = requests.get(findings_url, headers=headers, params=params, verify=False)
        response.raise_for_status()
        json_data = response.json()

        # Extract only the required fields from each finding
        return [
            {field: finding.get(field) for field in required_fields}
            for finding in json_data.get("results", [])
        ]
    except requests.exceptions.RequestException as e:
        print("Error fetching findings:", e)
        return []

def load_existing_data(file_path):
    """
    Load existing data from the file to avoid duplicates.
    """
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r") as file:
        return [json.loads(line) for line in file]

def integrate_data(findings, products, existing_data):
    """
    Integrate findings with product data and avoid duplicates.
    """
    existing_ids = {entry["id"] for entry in existing_data}
    new_entries = []

    for finding in findings:
        if finding["id"] not in existing_ids:
            matched_name = None

            # Check if the finding id matches any findings_list in products
            for product in products:
                if finding["id"] in product["findings_list"]:
                    matched_name = product["name"]
                    break
            # Add the matched name to the finding
            finding_with_product = finding.copy()
            finding_with_product["product_name"] = matched_name
            new_entries.append(finding_with_product)

    return new_entries

def save_new_data(file_path, existing_data, new_entries):
    """
    Save new data to the file only if there are new entries
    """
    if not new_entries:
        print("No new findings to add. Files remains unchanged.")
        return

    updated_data = existing_data + new_entries
    with open(file_path, "w") as file:
        for entry in updated_data:
            file.write(json.dumps(entry) + "\n")
    print(f"{len(new_entries)} new findings added to {file_path}")

# Main Execution
try:
    # Fetch data
    products = fetch_products()
    findings = fetch_findings()

    # Load existing data
    existing_data = load_existing_data(output_file)

    # Integrate findings with products
    new_entries = integrate_data(findings, products, existing_data)

    # Save integrated data to the file
    save_new_data(output_file, existing_data, new_entries)

except Exception as e:
    print("An error occurred during processing:", e)