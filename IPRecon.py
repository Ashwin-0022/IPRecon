import requests
import json
import csv
from tabulate import tabulate

ascii_art = r"""
  ___ ____  ____                      
 |_ _|  _ \|  _ \ ___  ___ ___  _ __  
  | || |_) | |_) / _ \/ __/ _ \| '_ \ 
  | ||  __/|  _ <  __/ (_| (_) | | | |
 |___|_|   |_| \_\___|\___\___/|_| |_|
"""
print(ascii_art)


# Function to read API keys from a file
def get_api_keys(file_path):
    api_keys = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    api_keys[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return api_keys

# Read API keys
api_keys = get_api_keys("api.txt")
abuseip_key = api_keys.get("Abuseip")
greynoise_key = api_keys.get("Greynoise")

if not abuseip_key or not greynoise_key:
    print("Error: Missing API keys in api.txt.")
    exit()

# Read IPs from file (supporting both comma-separated and newline-separated IPs)
with open("ip.txt", "r") as file:
    ip_list = [ip.strip() for ip in file.read().replace(",", "\n").splitlines() if ip.strip()]

table_data = []

for i in ip_list:
    ip_addr = i

    #-------------------------------------------------------------------------------------------------
    
    # AbuseIPDB request
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_addr,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseip_key
    }
    response = requests.get(url, headers=headers, params=querystring)

    # Decode the response
    decodedResponse = json.loads(response.text)

    ip_address = decodedResponse['data']['ipAddress']
    domain = decodedResponse['data']['domain']
    abuse_score = decodedResponse['data']['abuseConfidenceScore']

    #-------------------------------------------------------------------------------------------------
    
    # GreyNoise request
    url = f"https://api.greynoise.io/v3/community/{ip_addr}"
    headers = {
        'key': greynoise_key
    }
    response = requests.get(url, headers=headers)

    data = response.json()
    classification_data = data.get('classification', 'Not Found')

    #-------------------------------------------------------------------------------------------------

    table_data.append([ip_address, domain, abuse_score, classification_data])

# Save the data to a CSV file
output_file = "output.csv"
with open(output_file, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["IP", "Domain", "AbuseIP", "GreyNoise"])
    writer.writerows(table_data)

# Print the table
headers = ["IP", "Domain", "AbuseIP", "GreyNoise"]
print(tabulate(table_data, headers=headers, tablefmt="grid"))

print(f"Output saved to {output_file}")
input("Press Enter to exit...")
