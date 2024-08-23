import azure.functions as func
import datetime
import json
import logging
from bs4 import BeautifulSoup
import re
import os
import requests
import phonenumbers

app = func.FunctionApp()

@app.route(route="forwarded_email_reader", auth_level=func.AuthLevel.ANONYMOUS)
def python_function_azure(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    

    try:
        req_body = req.get_json()
        # Check for source in the request body
        source = None
        if 'rightmove' in json.dumps(req_body).lower():
            source = 'rightmove'
        elif 'zoopla' in json.dumps(req_body).lower():
            source = 'Zoopla'
        elif 'onthemarket' in json.dumps(req_body).lower():
            source = 'OnTheMarket'
        
        if source:
            logging.info(f"Source: {source}")
        else:
            logging.info("No recognized source found in the request body")
        
        email_body = req_body.get('emailBody')
        if email_body:
            # Remove HTML tags from the email body
            soup = BeautifulSoup(email_body, 'html.parser')
            plain_text = soup.get_text(separator=' ', strip=True)
            

            # Extract information based on the source
            if source == 'rightmove':
                name = extract_info(plain_text, r'Name:(.*?);')
                address = extract_info(plain_text, r'Address:(.*?);')
                email = extract_info(plain_text, r'Email:(.*?);')
                phone = extract_info(plain_text, r'Phone:(.*?);')
            elif source == 'onthemarket':
                name = extract_info(plain_text, r'Name:(.*?);')
                address = extract_info(plain_text, r'Address:(.*?);')
                email = extract_info(plain_text, r'Email:(.*?);')
                phone = extract_info(plain_text, r'Phone:(.*?);')

            elif source == 'zoopla':
                name = extract_info(plain_text, r'Name:\s*(.*?)(?:\r?\n|\r|$)', r'Telephone:')
                phone = extract_info(plain_text, r'Telephone:\s*(.*?)(?:\r?\n|\r|$)', r'Email:')
                email = extract_info(plain_text, r'Email:\s*(.*?)(?:\r?\n|\r|$)', r'Type of enquiry:')
                address = extract_info(plain_text, r'Address:\s*(.*?)(?:\r?\n|\r|$)', r'Message:')

            else:
                # For other sources, you might need to implement different extraction logic
                name = address = email = phone = "Extraction not implemented for this source"

            # Format the phone number
            phone = format_phone_number(phone)

            lead_info = {
                "name": name,
                "email": email,
                "phone": phone,
                "address": address,
                "source": source,
            }
            
            logging.info(f"Extracted lead information: {lead_info}")
            
            
            api_base_url = os.environ["API_BASE_URL"]
            x_auth_key = os.environ["X_AUTH_KEY"]

            # Prepare the payload
            payload = {
               
                "tenant_id": 15,
                "title": f"{source} Viewing Request",
                "summary": json.dumps(lead_info),
                "status": "pending",
                "team_member_id": 9,
                "workflow_id": None,
                "conversation_id": "123456"
            }

            # Prepare headers with x-auth-key
            headers = {
                "x-auth-key": x_auth_key,
                "Content-Type": "application/json"
            }

            # Log the request body
            logging.info(f"Request body: {payload}")

            try:
                # Make the POST request to the API with headers
                response = requests.post(f"{api_base_url}/api/tickets", json=payload, headers=headers)
                response.raise_for_status()  # Raise an exception for bad status codes
                
                logging.info(f"Successfully posted lead information to API. Response: {response.text}")
                return func.HttpResponse(json.dumps(lead_info), mimetype="application/json", status_code=200)
            except requests.RequestException as e:
                error_details = {
                    "error": str(e),
                    "api_url": f"{api_base_url}/api/tickets",
                    "status_code": e.response.status_code if hasattr(e, 'response') else None,
                    "response_text": e.response.text if hasattr(e, 'response') else None
                }
                logging.error(f"Failed to post lead information to API. Error details: {error_details}")
                return func.HttpResponse(
                    json.dumps({"error": "Failed to post lead information to API", "details": error_details}),
                    mimetype="application/json",
                    status_code=500
                )
        else:
            logging.warning("No email body found in the request payload")
            return func.HttpResponse("No email body found in the request payload", status_code=400)
    except ValueError:
        logging.error("Invalid JSON in request body")
        return func.HttpResponse("Invalid request body", status_code=400)

def extract_info(text, pattern, end_pattern=None):
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        if end_pattern:
            end = re.search(end_pattern, match.group(1))
            return match.group(1)[:end.start()].strip() if end else match.group(1).strip()
        return match.group(1).strip()
    return None

def format_phone_number(phone):
    if phone is None:
        return None
    
    # Remove all non-digit characters
    phone = re.sub(r'\D', '', phone)
    
    try:
        # Parse the phone number
        parsed_number = phonenumbers.parse(phone, "GB")
        
        # Format the number in E.164 format
        formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        
        # Remove the '+' sign from the beginning
        return formatted_number[1:]
    except phonenumbers.NumberParseException:
        # If parsing fails, return the original number
        return phone