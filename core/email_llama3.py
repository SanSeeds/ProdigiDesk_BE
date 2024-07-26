import os
from django.conf import settings
from groq import Groq
import requests
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from better_profanity import profanity
from django.http import JsonResponse, HttpResponse
from docx import Document as DocxDocument
import fitz  # PyMuPDF
import openpyxl
import xlrd

# API Keys
GROQ_SECRET_ACCESS_KEY = settings.GROQ_SECRET_ACCESS_KEY
BHASHINI_API_KEY = settings.BHASHINI_API_KEY
BHASHINI_USER_ID = settings.BHASHINI_USER_ID

# Function to check for inappropriate language
def contains_inappropriate_language(text: str) -> bool:
    inappropriate_words = ["stupid", "idiot", "badword3"]
    return any(word in text.lower() for word in inappropriate_words)

# Function to sanitize input containing inappropriate words
def sanitize_input(input_str):
    return profanity.censor(input_str)

#os.environ["GROQ_SECRET_ACCESS_KEY"] = GROQ_SECRET_ACCESS_KEY


# # Function to generate email
# def generate_email(purpose, num_words, subject, rephrase, to, tone, keywords, contextual_background, call_to_action, additional_details, priority_level, closing_remarks):
#     # Ensure all fields are checked for inappropriate language
#     fields_to_check = [purpose, subject, keywords, contextual_background, call_to_action, additional_details, closing_remarks]
#     if any(contains_inappropriate_language(str(field)) for field in fields_to_check if field is not None):
#         return "Error: Input contains inappropriate language."
    
#     prompt = f"Generate an email of maximum {num_words} words and subject: {subject}, to {to}, maintain a {tone} tone, using the following keywords {keywords}, given the following inputs:"
#     prompt += f"\nPurpose of the mail is {purpose}," if purpose else ""
#     prompt += f"\nConsider the contextual background {contextual_background}," if contextual_background else ""
#     prompt += f"\nWith an expectation of {call_to_action}," if call_to_action else ""
#     prompt += f"\nIncorporate the following additional details: {additional_details}." if additional_details else ""
#     prompt += f"\nThe mail is of {priority_level} priority." if priority_level else ""
#     prompt += f"\nIncorporate the closing remarks {closing_remarks}." if closing_remarks else ""
#     prompt += "\nRephrase the subject" if rephrase == "Y" else ""
    
#     client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)
#     chat_completion = client.chat.completions.create(
#         messages=[{"role": "user", "content": prompt}],
#         model="llama3-70b-8192"
#     )
    
#     return chat_completion.choices[0].message.content


# Function to generate email
# def generate_email(purpose, num_words, subject, rephrase, to, tone, keywords, contextual_background, call_to_action, additional_details, priority_level, closing_remarks):
#     # Ensure all fields are checked for inappropriate language
#     fields_to_check = [purpose, subject, keywords, contextual_background, call_to_action, additional_details, closing_remarks]
#     if any(contains_inappropriate_language(str(field)) for field in fields_to_check if field is not None):
#         return "Error: Input contains inappropriate language."
    
#     prompt = f"Generate an email of maximum {num_words} words and subject: {subject}, to {to}, maintain a {tone} tone, using the following keywords {keywords}, given the following inputs:"
#     prompt += f"\nPurpose of the mail is {purpose}," if purpose else ""
#     prompt += f"\nConsider the contextual background {contextual_background}," if contextual_background else ""
#     prompt += f"\nWith an expectation of {call_to_action}," if call_to_action else ""
#     prompt += f"\nIncorporate the following additional details: {additional_details}." if additional_details else ""
#     prompt += f"\nThe mail is of {priority_level} priority." if priority_level else ""
#     prompt += f"\nIncorporate the closing remarks {closing_remarks}." if closing_remarks else ""
#     prompt += "\nRephrase the subject" if rephrase == "Y" else ""
    
#     client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)
#     chat_completion = client.chat.completions.create(
#         messages=[{"role": "user", "content": prompt}],
#         model="llama3-70b-8192"
#     )
    
#     return chat_completion.choices[0].message.content

def generate_email(purpose, num_words, subject, rephrase, to, tone, keywords, contextual_background, call_to_action, additional_details, priority_level, closing_remarks):
    # Ensure all fields are checked for inappropriate language
    fields_to_check = [purpose, subject, keywords, contextual_background, call_to_action, additional_details, closing_remarks]
    if any(contains_inappropriate_language(str(field)) for field in fields_to_check if field is not None):
        return "Error: Input contains inappropriate language."
    
    prompt = f"Generate an email of maximum {num_words} words and subject: {subject}, to {to}, maintain a {tone} tone, using the following keywords {', '.join(keywords)}, given the following inputs:"
    prompt += f"\nPurpose of the mail is {purpose}," if purpose else ""
    prompt += f"\nConsider the contextual background {contextual_background}," if contextual_background else ""
    prompt += f"\nWith an expectation of {call_to_action}," if call_to_action else ""
    prompt += f"\nIncorporate the following additional details: {additional_details}." if additional_details else ""
    prompt += f"\nThe mail is of {priority_level} priority." if priority_level else ""
    prompt += f"\nIncorporate the closing remarks {closing_remarks}." if closing_remarks else ""
    prompt += "\nRephrase the subject" if rephrase == "Y" else ""
    
    client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama3-70b-8192"
    )
    
    return chat_completion.choices[0].message.content


# #text = generate_email("confirm details", "100", "Require Contact Details","Y" ,"client", "formal", "SPOC, AI, contract, project, deadline, payment", "Had a conversation with VP last week regarding an AI project on contract basis. Looking for further updates","meeting","","High","")
# def generate_bus_pro(business_intro, proposal_objective, num_words, scope_of_work, project_phases, expected_outcomes, innovative_approaches, technologies_used, target_audience,budget_info,timeline,benefits, closing_remarks):
#     prompt = f"Generate an business proposal of maximum {num_words} words, given the following inputs: "
#     if business_intro:
#         prompt = prompt+ "\n" + f"Our business details are {business_intro}, "
#     if proposal_objective:
#         prompt = prompt+ "\n" + f"and the purpose of this proposal is {proposal_objective}, "
#     if scope_of_work:
#         prompt = prompt + "\n"+ f"Define the scope of work as {scope_of_work}. "
#     if project_phases:
#         prompt = prompt+ "\n" + f"The project will be done in the following phases: {project_phases}. "
#     if expected_outcomes:
#         prompt = prompt + "\n"+f"Reprise the client of these expected outcomes: {expected_outcomes}. "
#     if innovative_approaches:
#         prompt = prompt + "\n"+f"Mention our following innovative approach: {innovative_approaches}, "
#     if technologies_used:
#         prompt = prompt + "\n"+f"and following technologies_used: {technologies_used}. "
#     if budget_info:
#         prompt = prompt + "\n"+f"Incorporate this budget_info: {budget_info}. "
#     if target_audience:
#         prompt = prompt + "\n"+f"Bear in mind that the target_audience is: {target_audience}. "
#     if timeline:
#         prompt = prompt + "\n"+f"The timelines we hope to stick to is : {timeline}. "
#     if benefits:
#         prompt = prompt + "\n"+f"Incorporate into the proposal the following benefits : {benefits}. "
#     if closing_remarks:
#         prompt = prompt+ "\n" + f"Incorporate the following closing remarks {closing_remarks}. "

#     client = Groq(
#         api_key=GROQ_SECRET_ACCESS_KEY   #os.environ.get("GROQ_API_KEY"),
#     )

#     chat_completion = client.chat.completions.create(
#         messages=[
#             {
#                 "role": "user",
#                 "content": prompt,
#             }
#         ],
#         model="llama3-70b-8192",
#     )

#     # print(chat_completion.choices[0].message.content)
#     return(chat_completion.choices[0].message.content)



def generate_bus_pro(business_intro, proposal_objective, num_words, scope_of_work, project_phases, expected_outcomes, tech_innovations, target_audience, budget_info, timeline, benefits, closing_remarks):
    prompt = f"Generate a business proposal of maximum {num_words} words, given the following inputs: "
    if business_intro:
        prompt += f"Our business details are {business_intro}, "
    if proposal_objective:
        prompt += f"and the purpose of this proposal is {proposal_objective}, "
    if scope_of_work:
        prompt += f"Define the scope of work as {scope_of_work}. "
    if project_phases:
        prompt += f"The project will be done in the following phases: {project_phases}. "
    if expected_outcomes:
        prompt += f"Reprise the client of these expected outcomes: {expected_outcomes}. "
    if tech_innovations:
        prompt += f"Mention our following technologies and innovative approaches: {tech_innovations}. "
    if target_audience:
        prompt += f"Bear in mind that the target audience is: {target_audience}. "
    if budget_info:
        prompt += f"Incorporate this budget info: {budget_info}. "
    if timeline:
        prompt += f"The timelines we hope to stick to are: {timeline}. "
    if benefits:
        prompt += f"Incorporate into the proposal the following benefits: {benefits}. "
    if closing_remarks:
        prompt += f"Incorporate the following closing remarks: {closing_remarks}. "

    client = Groq(
        api_key=GROQ_SECRET_ACCESS_KEY,
    )

    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-70b-8192",
    )

    return chat_completion.choices[0].message.content


# def generate_offer_letter(company_details,num_words, candidate_name, position_title, department, supervisor, status,location,
#                           start_date, compensation, benefits, work_hours, duration,terms, acceptance_deadline,
#                           contact_info, documents_needed, closing_remarks):
#     prompt = f"Generate an offer letter of maximum {num_words} words, given the following inputs: "
#     if company_details:
#         prompt = prompt+ "\n" + f"Our business details are {company_details}, "
#     if candidate_name:
#         prompt = prompt+ "\n" + f"Candidate name is {candidate_name}, "
#     if position_title:
#         prompt = prompt + "\n"+ f"for the position of {position_title}, "
#     if department:
#         prompt = prompt+ "\n" + f"in the department: {department}, "
#     if supervisor:
#         prompt = prompt + "\n"+f"under the supervisor: {supervisor}. "
#     if status:
#         prompt = prompt + "\n"+f"as a {status} employee. "
#     if location:
#         prompt = prompt + "\n"+f"Expected to work from: {location}. "
#     if start_date:
#         prompt = prompt + "\n"+f"Candidate to join on {start_date}. "
#     if compensation:
#         prompt = prompt + "\n"+f"Candidate will be given a compensation of: {compensation}. "
#     if benefits:
#         prompt = prompt + "\n"+f"Added to the compensation there will be following benefits : {benefits}. "
#     if work_hours:
#         prompt = prompt + "\n"+f"Expected working hours : {work_hours}. "
#     if duration:
#         prompt = prompt + "\n"+f"for a duration of: {duration}. "
#     if terms:
#         prompt = prompt + "\n"+f"Following are the terms of offer: {terms}. "
#     if acceptance_deadline:
#         prompt = prompt + "\n"+f"the last day for accepting the offer is: {acceptance_deadline}. "
#     if contact_info:
#         prompt = prompt + "\n"+f"In case of any queries contact : {contact_info}. "
#     if documents_needed:
#         prompt = prompt + "\n"+f"Following documents to be produced on the day of joining: {documents_needed}. "

#     if closing_remarks:
#         prompt = prompt+ "\n" + f"Incorporate the following closing remarks in the offer letter {closing_remarks}. "

#     client = Groq(
#         api_key=GROQ_SECRET_ACCESS_KEY   #os.environ.get("GROQ_API_KEY"),
#     )

#     chat_completion = client.chat.completions.create(
#         messages=[
#             {
#                 "role": "user",
#                 "content": prompt,
#             }
#         ],
#         model="llama3-70b-8192",
#     )

#     # print(chat_completion.choices[0].message.content)
#     return(chat_completion.choices[0].message.content)

def generate_offer_letter(company_details, candidate_name, position_title, department, status, location,
                          start_date, compensation_benefits, work_hours, terms, acceptance_deadline,
                          contact_info, documents_needed, closing_remarks):
    # Start building the prompt
    prompt = "Generate an offer letter given the following inputs: "
    
    if company_details:
        prompt += f"\nOur business details are {company_details}, "
    if candidate_name:
        prompt += f"\nCandidate name is {candidate_name}, "
    if position_title:
        prompt += f"\nfor the position of {position_title}, "
    if department:
        prompt += f"\nin the department: {department}, "
    if status:
        prompt += f"\nas a {status} employee. "
    if location:
        prompt += f"\nExpected to work from: {location}. "
    if start_date:
        prompt += f"\nCandidate to join on {start_date}. "
    if compensation_benefits:
        prompt += f"\nCandidate will receive the following compensation and benefits: {compensation_benefits}. "
    if work_hours:
        prompt += f"\nExpected working hours: {work_hours}. "
    if terms:
        prompt += f"\nFollowing are the terms of the offer: {terms}. "
    if acceptance_deadline:
        prompt += f"\nThe last day for accepting the offer is: {acceptance_deadline}. "
    if contact_info:
        prompt += f"\nIn case of any queries contact: {contact_info}. "
    if documents_needed:
        prompt += f"\nFollowing documents to be produced on the day of joining: {documents_needed}. "
    if closing_remarks:
        prompt += f"\nIncorporate the following closing remarks in the offer letter: {closing_remarks}. "

    # Initialize client with API key
    client = Groq(
        api_key=GROQ_SECRET_ACCESS_KEY   # os.environ.get("GROQ_API_KEY"),
    )

    # Create chat completion with the prompt
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-70b-8192",
    )

    # Return the generated content
    return chat_completion.choices[0].message.content


def generate_summary(document_context, main_subject, summary_purpose, length_detail, important_elements, audience, tone, format, additional_instructions, document):
    prompt = f"Generate a summary of the given document {document} given the following inputs: "
    if document:
    #     prompt = prompt + "\n"+f"Added to the compensation there will be following benefits : {document}. "
        if document_context:
            prompt = prompt+ "\n" + f"Context of document: {document_context}, "
        if main_subject:
            prompt = prompt+ "\n" + f"Main subject: {main_subject}, "
        if summary_purpose:
            prompt = prompt + "\n"+ f"Purpose of generating summary {summary_purpose}, "
        if length_detail:
            prompt = prompt+ "\n" + f"Level of detail: {length_detail}, "
        if important_elements:
            prompt = prompt + "\n"+f"Important elements: {important_elements}. "
        if audience:
            prompt = prompt + "\n"+f"Target audience:{audience}. "
        if tone:
            prompt = prompt + "\n"+f"Expected tone: {tone}. "
        if format:
            prompt = prompt + "\n"+f"Expected format {format}. "
        if additional_instructions:
            prompt = prompt + "\n"+f"Additional Instructions: {additional_instructions}. "

        client = Groq(
            api_key=GROQ_SECRET_ACCESS_KEY   #os.environ.get("GROQ_API_KEY"),
        )

        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama3-70b-8192",
        )

        # print(chat_completion.choices[0].message.content)
        return(chat_completion.choices[0].message.content)
    else:
        return("Error: Attach Document!!")


# Function to generate content based on provided parameters
def generate_content(company_info, content_purpose, desired_action, topic_details, keywords, audience_profile, format_structure, num_words, seo_keywords, references):
    inputs = {
        "company_info": company_info,
        "content_purpose": content_purpose,
        "desired_action": desired_action,
        "topic_details": topic_details,
        "keywords": keywords,
        "audience_profile": audience_profile,
        "format_structure": format_structure,
        "seo_keywords": seo_keywords,
        "references": references
    }

    # Initialize inappropriate_key and inappropriate_value to None
    inappropriate_key = None
    inappropriate_value = None

    # Check if any input parameter contains inappropriate words
    for key, value in inputs.items():
        if value and contains_inappropriate_language(value):
            inappropriate_key = key
            inappropriate_value = value
            break

    if inappropriate_key:
        return f"This type of language is not allowed in {inappropriate_key}: '{inappropriate_value}'."

    # Construct the prompt for content generation
    prompt = f"Generate high-quality, engaging content of maximum {num_words} words with the following details:\n"

    if company_info:
        prompt += f"Company Information: {sanitize_input(company_info)}\n"
    if content_purpose:
        prompt += f"Purpose of Content: {sanitize_input(content_purpose)}\n"
    if desired_action:
        prompt += f"Desired Action: {sanitize_input(desired_action)}\n"
    if topic_details:
        prompt += f"Topic Details: {sanitize_input(topic_details)}\n"
    if keywords:
        prompt += f"Keywords: {sanitize_input(keywords)}\n"
    if audience_profile:
        prompt += f"Audience Profile: {sanitize_input(audience_profile)}\n"
    if format_structure:
        prompt += f"Format and Structure: {sanitize_input(format_structure)}\n"
    if seo_keywords:
        prompt += f"SEO Keywords: {sanitize_input(seo_keywords)}\n"
    if references:
        prompt += f"References to Cite: {sanitize_input(references)}\n"

    # Additional instructions for the content creation
    prompt += (
        "\nInstructions:\n"
        "- Ensure the content is engaging, informative, and relevant to the specified audience.\n"
        "- Highlight the benefits and unique aspects of the topic to capture the audience's interest.\n"
        "- Use a professional tone and clear language to communicate effectively.\n"
        "- Incorporate the provided keywords naturally and strategically for SEO optimization.\n"
        "- Maintain accuracy and avoid any hallucinations or false information.\n"
        "- Adhere to the specified format and structure to meet the content requirements.\n"
    )

    # Generate content using Groq API
    client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)

    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-70b-8192",
    )

    return chat_completion.choices[0].message.content

def generate_sales_script(company_details, num_words, product_descriptions, features_benefits, pricing_info, promotions, target_audience, sales_objectives,
                          competitive_advantage, compliance):
    inputs = {
        "Company Details": company_details,
        "Product Descriptions": product_descriptions,
        "Features and Benefits": features_benefits,
        "Pricing Info": pricing_info,
        "Promotions": promotions,
        "Target Audience": target_audience,
        "Sales Objectives": sales_objectives,
        "Competitive Advantage": competitive_advantage,
        "Compliance": compliance,
        "Number Of Words" : num_words
    }

    # Check if any input parameter contains inappropriate words
    inappropriate_key = None
    inappropriate_value = None
    for key, value in inputs.items():
        if value and contains_inappropriate_language(value):
            inappropriate_key = key
            inappropriate_value = value
            break

    if inappropriate_key:
        return f"This type of language is not allowed in {inappropriate_key}: {inappropriate_value}"

    # Build the prompt for generating the sales script
    prompt = f"Generate a sales script of maximum {num_words} words, given the following inputs: "
    for key, value in inputs.items():
        if value:
            prompt += f"\n- {key}: {value}"

    prompt += (
        "\n\nInstructions:\n"
        "- Ensure the script is professional and persuasive.\n"
        "- Avoid any hallucinations or fabricated information. Use only the provided details.\n"
        "- Maintain accuracy and factual integrity throughout the script.\n"
        "- Avoid using any inappropriate words or foul language."
    )

    client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)

    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-70b-8192",
    )

    return chat_completion.choices[0].message.content





def bhashini_translate(text: str,  to_code: str = "Hindi", from_code: str = "English",user_id: str=BHASHINI_USER_ID, api_key: str=BHASHINI_API_KEY) -> dict:
    """Translates text from source language to target language using the Bhashini API.

    Args:
        text (str): The text to translate.
        from_code (str): Source language code. Default is 'en' (English).
        to_code (str): Target language code. Default is 'te' (Telugu).
        user_id (str): User ID for the API.
        api_key (str): API key for authentication.

    Returns:
        dict: A dictionary with the status code, message, and translated text or error info.
    """
    lang_dict = {
        "English" :"en",
        "Hindi" :"hi",
        "Tamil" :"ta",
        "Telugu": "te",
        "Marathi": "mr",
        "Kannada" : "kn",
        "Bengali" : "bn",
        "Odia": "or",
        "Assamese": "as",
        "Punjabi": "pa",
        "Malayalam": "ml",
        "Gujarati": "gu",
        "Urdu" : "ur",
        "Sanskrit" : "sa",
        "Nepali" : "ne",
        "Bodo": "brx",
        "Maithili" : "mai",
        "Sindhi" : "sd",
        "Tamil" : "ta",

    }

    print(33333, text, 4444, to_code)
    from_code = lang_dict[from_code]
    to_code = lang_dict[to_code]
    print(222222, from_code, to_code)



    # Setup the initial request to get model configurations
    url = 'https://meity-auth.ulcacontrib.org/ulca/apis/v0/model/getModelsPipeline'
    headers = {
        "Content-Type": "application/json",
        "userID": user_id,
        "ulcaApiKey": api_key
    }
    payload = {
        "pipelineTasks": [{"taskType": "translation", "config": {"language": {"sourceLanguage": from_code, "targetLanguage": to_code}}}],
        "pipelineRequestConfig": {"pipelineId": "64392f96daac500b55c543cd"}
    }
    response = requests.post(url, json=payload, headers=headers)

    if response.status_code != 200:
        return {"status_code": response.status_code, "message": "Error in translation request", "translated_content": None}

    # Process the response to setup the translation execution
    response_data = response.json()
    service_id = response_data["pipelineResponseConfig"][0]["config"][0]["serviceId"]
    callback_url = response_data["pipelineInferenceAPIEndPoint"]["callbackUrl"]
    headers2 = {
        "Content-Type": "application/json",
        response_data["pipelineInferenceAPIEndPoint"]["inferenceApiKey"]["name"]: response_data["pipelineInferenceAPIEndPoint"]["inferenceApiKey"]["value"]
    }
    compute_payload = {
        "pipelineTasks": [{"taskType": "translation", "config": {"language": {"sourceLanguage": from_code, "targetLanguage": to_code}, "serviceId": service_id}}],
        "inputData": {"input": [{"source": text}], "audio": [{"audioContent": None}]}
    }

    # Execute the translation
    compute_response = requests.post(callback_url, json=compute_payload, headers=headers2)
    if compute_response.status_code != 200:
        return {"status_code": compute_response.status_code, "message": "Error in translation", "translated_content": None}

    compute_response_data = compute_response.json()
    translated_content = compute_response_data["pipelineResponse"][0]["output"][0]["target"]

    return {"status_code": 200, "message": "Translation successful", "translated_content": translated_content}


#print(bhashini_translate(text))
#translate_generated_text(text,"French")

def generate_slide_titles(title, num_slides, special_instructions):
    prompt = f"Generate titles for {num_slides} slides on the subject {title}. "
    if special_instructions:
        prompt += f"\nPay attention to the following points: {special_instructions} while generating titles. "
    prompt += f"Titles should be in the form of a python list object with {num_slides} elements. Output only the list object without any text before or after the list."

    client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama3-70b-8192",
    )
    title_list = chat_completion.choices[0].message.content
    return title_list


def generate_slide_content(st, title, special_instructions, document_content=None):
    prompt = f"Generate content to be put in ppt slide with title {st}. The overall subject of the presentation is {title}. "
    if special_instructions:
        prompt += f"\nPay attention to the following points: {special_instructions} while generating content. "
    if document_content:
        prompt += f"\nUse the following document content as a reference: {document_content[:2000]}... "
    prompt += (
        "Content should be in the form of bullet points and should be just sufficient to fit on a single slide. "
        "Output only the slide contents - avoid any text describing the content. "
        "Do not include title in the content. No bold text. Avoid the text 'Here is the content for the PPT slide'. "
        "Do not include the bullet point symbols."
    )

    client = Groq(api_key=GROQ_SECRET_ACCESS_KEY)
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama3-70b-8192",
    )
    slide_content = chat_completion.choices[0].message.content
    return slide_content


def add_slide(prs, title, content, bg_image):
    slide_layout = prs.slide_layouts[1]
    slide = prs.slides.add_slide(slide_layout)

    title_placeholder = slide.shapes.title
    content_placeholder = slide.placeholders[1]

    title_text_frame = title_placeholder.text_frame
    title_font_size = Pt(32)
    small_font_size = Pt(20)
    title_text_frame.clear()

    p = title_text_frame.paragraphs[0]
    run = p.add_run()
    run.text = title.split("(contd.)")[0]
    run.font.size = title_font_size
    run.font.bold = True
    run.font.color.rgb = RGBColor(0, 51, 102)

    if "(contd.)" in title:
        run = p.add_run()
        run.text = "(contd.)"
        run.font.size = small_font_size
        run.font.bold = True
        run.font.color.rgb = RGBColor(0, 51, 102)

    p.alignment = PP_ALIGN.CENTER

    content_text_frame = content_placeholder.text_frame
    content_font_size = Pt(18)
    content_text_frame.paragraphs[0].font.size = content_font_size
    content_text_frame.paragraphs[0].font.color.rgb = RGBColor(0, 0, 0)
    content_text_frame.paragraphs[0].alignment = PP_ALIGN.LEFT

    content_text_frame.text = '\n'.join(content)

    if bg_image is None:
        bg_image = settings.DEFAULT_BACKGROUND_IMAGE_PATH

    left = top = Inches(0)
    pic = slide.shapes.add_picture(bg_image, left, top, width=prs.slide_width, height=prs.slide_height)
    slide.shapes._spTree.remove(pic._element)
    slide.shapes._spTree.insert(2, pic._element)


def create_presentation(title, num_slides, special_instructions, bg_image):
    prs = Presentation()
    slide_titles = generate_slide_titles(title, num_slides, special_instructions)
    slide_titles = slide_titles.replace('[', '').replace(']', '').replace('"', '').split(',')

    max_points_per_slide = 4

    for st in slide_titles:
        slide_content = generate_slide_content(st, title, special_instructions).replace("*", '').split('\n')
        current_content = []
        slide_count = 1

        for point in slide_content:
            current_content.append(point.strip())
            if len(current_content) >= max_points_per_slide:
                add_slide(prs, st if slide_count == 1 else f"{st} (contd.)", current_content, bg_image)
                current_content = []
                slide_count += 1

        if current_content:
            add_slide(prs, st if slide_count == 1 else f"{st} (contd.)", current_content, bg_image)

    return prs








def extract_document_content(file_path):
    if file_path.endswith('.docx'):
        doc = DocxDocument(file_path)
        return '\n'.join([para.text for para in doc.paragraphs])
    elif file_path.endswith('.pdf'):
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    elif file_path.endswith('.xlsx'):
        wb = openpyxl.load_workbook(file_path)
        sheet = wb.active
        text = ""
        for row in sheet.iter_rows(values_only=True):
            text += ' '.join([str(cell) for cell in row if cell is not None]) + '\n'
        return text
    elif file_path.endswith('.xls'):
        wb = xlrd.open_workbook(file_path)
        sheet = wb.sheet_by_index(0)
        text = ""
        for row_idx in range(sheet.nrows):
            row = sheet.row(row_idx)
            text += ' '.join([str(cell.value) for cell in row if cell.value]) + '\n'
        return text
    else:
        raise ValueError("Unsupported file type")




