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
        #logging.info(f"Received request body: {json.dumps(req_body)}")
        # Check for source in the request body
        source = None
        if 'rightmove' in json.dumps(req_body).lower():
            source = 'Rightmove'
        elif 'zoopla' in json.dumps(req_body).lower():
            source = 'Zoopla'
        elif 'onthemarket' in json.dumps(req_body).lower():
            source = 'OnTheMarket'
        
        if source:
            logging.info(f"Source identified: {source}")
        else:
            logging.warning("No recognized source found in the request body")
        
        email_body = req_body.get('emailBody')
        if email_body:
            logging.info("Email body found in request")
            # Remove HTML tags from the email body
            soup = BeautifulSoup(email_body, 'html.parser')
            plain_text = soup.get_text(separator=' ', strip=True)
            logging.info(f"Parsed plain text: {plain_text[:200]}...")  # Log first 200 characters
            
            # Extract information based on the source
            if source == 'Rightmove':
                name = extract_info(plain_text, r'Name:(.*?);')
                address = extract_info(plain_text, r'Address:(.*?);')
                email = extract_info(plain_text, r'Email:(.*?);')
                phone = extract_info(plain_text, r'Phone:(.*?);')
            elif source == 'OnTheMarket':
                name = extract_info(plain_text, r'Name:(.*?);')
                address = extract_info(plain_text, r'Address:(.*?);')
                email = extract_info(plain_text, r'Email:(.*?);')
                phone = extract_info(plain_text, r'Phone:(.*?);')
            elif source == 'Zoopla':
                name = extract_info(plain_text, r'Name:\s*(.*?)(?:\r?\n|\r|$)', r'Telephone:')
                phone = extract_info(plain_text, r'Telephone:\s*(.*?)(?:\r?\n|\r|$)', r'Email:')
                email = extract_info(plain_text, r'Email:\s*(.*?)(?:\r?\n|\r|$)', r'Type of enquiry:')
                address = extract_info(plain_text, r'Address:\s*(.*?)(?:\r?\n|\r|$)', r'Message:')
            else:
                # For other sources, you might need to implement different extraction logic
                name = address = email = phone = "Extraction not implemented for this source"

            logging.info(f"Extracted raw information - Name: {name}, Address: {address}, Email: {email}, Phone: {phone}")

            # Format the phone number
            phone = format_phone_number(phone)
            logging.info(f"Formatted phone number: {phone}")

            # Clean the email address
            email = clean_email(email)
            logging.info(f"Cleaned email address: {email}")

            if address is None:
                address = "No Address Listed"
        


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
            logging.info(f"API Base URL: {api_base_url}")

            # After converting the email to the required format, use it to search for the user in the database
            # If the user is found, use their ID in the payload
            # If the user is not found, create a new user and use their ID in the payload 
            def get_or_create_user(email, name, phone, address):
                # Search for the user in the database
                search_url = f"{api_base_url}/api/tenants/phone"
                search_headers = {
                    "x-auth-key": x_auth_key,
                    "Content-Type": "application/json"
                }
                
                search_body = {
                    "phone": phone
                }
                
                logging.info(f"Search body: {search_body}")
                
                try:
                    logging.info(f"Searching for user with phone: {phone}")
                    search_response = requests.post('http://51.21.6.228/api/tenants/phone', headers=search_headers, json=search_body)
                    
                    if search_response.status_code == 200:
                        search_data = search_response.json()
                        logging.info(f"Response Content: {search_response.content}")
                        logging.info(f"Search response: {search_data}")

                        if search_data.get("data"):
                            # User found, return their ID
                            user_id = search_data["data"]["tenant_id"]
                            logging.info(f"Existing user found with ID: {user_id}")
                            return user_id
                    
                    # If status code is 404 or any other non-200 status, proceed to create a new user
                    logging.info("User not found or EError occurred, creating new user")
                    # User not found, create a new user
                    # First, get the property_id using the postcode
                    # TODO: Make this dynamic
                    property_id = 1
                    if address and address != "No Address Listed":
                        postcode = "NN8%20123"
                        #postcode = extract_postcode("NN8%20123")
                        logging.info(f"Extracted postcode: {postcode}")
                        property_url = f"{api_base_url}/api/properties/find?Postcode={postcode}"
                        property_response = requests.get(property_url, headers=search_headers)
                        property_response.raise_for_status()
                        property_data = property_response.json()
                        
                        if property_data.get("data"):
                            property_id = property_data["data"][0]["id"]
                            logging.info(f"Found property ID: {property_id}")
                        else:
                            logging.warning(f"No property found for postcode: {postcode}")
                    else:
                        logging.info("No address provided, setting property_id to 0")
                    
                    # Create new user payload
                    new_user_payload = {
                        "name": name,
                        "email": email,
                        "country_code": "+44",  # Default to UK
                        "phone": phone,
                        "address": address if address else "No Address Listed",
                        "status": "prospect",
                        "organisation_id": 4,
                        "property_id": property_id,
                        "additional_information": {}
                    }
                    
                    logging.info(f"New user payload: {new_user_payload}")
                    # Create new user
                    create_url = f"{api_base_url}/api/tenants/create-tenant"
                    create_headers = {
                        "x-auth-key": x_auth_key,
                        "Content-Type": "application/json"
                    }
                    logging.info(f"Creating new user with payload: {new_user_payload}")
                    create_response = requests.post(create_url, json=new_user_payload, headers=create_headers)
                    create_response.raise_for_status()
                    create_data = create_response.json()
                    
                    new_user_id = create_data["data"]["tenant_id"]
                    logging.info(f"New user created with ID: {new_user_id}")
                    return new_user_id
                
                except requests.RequestException as e:
                    logging.error(f"Error in get_or_create_user: {str(e)}")
                    raise

            # Use the function to get or create user
            tenant_id = get_or_create_user(email, name, phone, lead_info["address"])
            logging.info(f"Tenant ID for payload: {tenant_id}")
            # Prepare the payload
            payload = {
                "tenant_id": tenant_id,
                "title": f"{source} Viewing Request",
                "summary": json.dumps(lead_info),
                "status": "pending",
                "team_member_id": 1,
                "workflow_id": 1,
                "conversation_id": "123456"
            }

            # Prepare headers with x-auth-key
            headers = {
                "x-auth-key": x_auth_key,
                "Content-Type": "application/json"
            }

            # Log the request body
            logging.info(f"Request body for API: {payload}")

            try:
                # Make the POST request to the API with headers
                api_url = f"{api_base_url}/api/tickets"
                logging.info(f"Sending POST request to: {api_url}")
                response = requests.post(api_url, json=payload, headers=headers)
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
    except json.JSONDecodeError:
        logging.error("Invalid JSON in request body")
        return func.HttpResponse("Invalid JSON in request body", status_code=400)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(f"An unexpected error occurred: {str(e)}", status_code=500)

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
    
def extract_postcode(address):
    # Simple regex to extract postcode from address
    postcode_match = re.search(r'\b[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}\b', address)
    if postcode_match:
        return postcode_match.group()
    else:
        raise ValueError("No valid postcode found in the address")

def clean_email(email):
    if email is None:
        return None
    
    # Use regex to extract just the email address
    email_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email)
    if email_match:
        return email_match.group()
    else:
        return None