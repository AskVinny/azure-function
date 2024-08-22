import azure.functions as func
import datetime
import json
import logging
from bs4 import BeautifulSoup
import re
import os
import requests

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
            source = 'zoopla'
        elif 'onthemarket' in json.dumps(req_body).lower():
            source = 'onthemarket'
        
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
                requirements = extract_info(plain_text, r'Requirements:(.*?);')
                prop_description = extract_info(plain_text, r'PropDescription:(.*?);')
                prop_address = extract_info(plain_text, r'PropAddress:(.*?);')
                prop_price = extract_info(plain_text, r'PropPrice:(.*?);')
                prop_reference = extract_info(plain_text, r'PropReference:(.*?);')
                consent = extract_info(plain_text, r'Consent:(.*?);')
                branch = extract_info(plain_text, r'Branch:(.*?);')
                enquiry_type = extract_info(plain_text, r'EnquiryType:(.*?);')
            elif source == 'zoopla':
                name = extract_info(plain_text, r'Name:\s*(.*?)(?:\r?\n|\r|$)')
                phone = extract_info(plain_text, r'Telephone:\s*(.*?)(?:\r?\n|\r|$)')
                email = extract_info(plain_text, r'Email:\s*(.*?)(?:\r?\n|\r|$)')
                enquiry_type = extract_info(plain_text, r'Type of enquiry:\s*(.*?)(?:\r?\n|\r|$)')
                unique_reference = extract_info(plain_text, r'Unique Reference:\s*(.*?)(?:\r?\n|\r|$)')
                prop_reference = extract_info(plain_text, r'Your property ref:\s*(.*?)(?:\r?\n|\r|$)')
                prop_address = extract_info(plain_text, r'Address:\s*(.*?)(?:\r?\n|\r|$)')
                prop_price = extract_info(plain_text, r'£([\d,]+)\s*pcm')
                prop_description = extract_info(plain_text, r'(?:£[\d,]+\s*pcm\s*-\s*)(.*?)(?:\r?\n|\r|$)')
                location = extract_info(plain_text, r'Location:\s*(.*?)(?:\r?\n|\r|$)')
                property_type = extract_info(plain_text, r'Type of property:\s*(.*?)(?:\r?\n|\r|$)')
                price_range = extract_info(plain_text, r'Price range:\s*(.*?)(?:\r?\n|\r|$)')
            else:
                # For other sources, you might need to implement different extraction logic
                name = address = email = phone = "Extraction not implemented for this source"

            lead_info = {
                "name": name,
                "email": email,
                "phone": phone
            }
            
            if source == 'onthemarket':
                lead_info.update({
                    "address": address,
                    "requirements": requirements,
                    "property_description": prop_description,
                    "property_address": prop_address,
                    "property_price": prop_price,
                    "property_reference": prop_reference,
                    "consent": consent,
                    "branch": branch,
                    "enquiry_type": enquiry_type
                })
            elif source == 'zoopla':
                lead_info.update({
                    "enquiry_type": enquiry_type,
                    "unique_reference": unique_reference,
                    "property_reference": prop_reference,
                    "property_address": prop_address,
                    "property_price": prop_price,
                    "property_description": prop_description,
                    "location": location,
                    "property_type": property_type,
                    "price_range": price_range
                })
            
            logging.info(f"Extracted lead information: {lead_info}")
            
            
            api_base_url = os.environ["API_BASE_URL"]
            x_auth_key = os.environ["X_AUTH_KEY"]

            # Prepare the payload
            payload = {
                "tenant_id": 15,
                "title": "New Viewing Request has been created",
                "summary": lead_info,
                "status": "open",
                "team_member_id": 1,
                "workflow_id": None,
                "conversation_id": "123456"
            }

            # Prepare headers with x-auth-key
            headers = {
                "x-auth-key": x_auth_key,
                "Content-Type": "application/json"
            }

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
                    "response_text": e.response.text if hasattr(e, 'response') else None,
                    "request_body": json.dumps(payload)
                }
                logging.error(f"Failed to post lead information to API. Error details: {json.dumps(error_details)}")
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

def extract_info(text, pattern):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else "Not found"