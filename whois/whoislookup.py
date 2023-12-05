import argparse
import whois

def get_whois_info(domain_name):
    try:
        whois_info = whois.whois(domain_name)
        return whois_info
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrieve WHOIS information for a domain.")
    parser.add_argument("-u", "--url", required=True, help="URL for which to retrieve WHOIS information")
    args = parser.parse_args()
    
    domain_name = args.url
    whois_info = get_whois_info(domain_name)
    
    if isinstance(whois_info, dict):
        for key, value in whois_info.items():
            print(f"{key}: {value}")
    else:
        print(f"Error: {whois_info}")
