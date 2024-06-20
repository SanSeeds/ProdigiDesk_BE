import os
from groq import Groq
GROQ_SECRET_ACCESS_KEY="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"

#os.environ["GROQ_SECRET_ACCESS_KEY"] = GROQ_SECRET_ACCESS_KEY


def generate_email(purpose, num_words, subject, rephrase, to, tone, keywords, contextual_background, call_to_action, additional_details,priority_level,closing_remarks):
    prompt = f"Generate an email of maximum {num_words} words and subject: {subject}, to {to}  ,maintain a {tone} tone, using the following keywords {keywords}, given the following inputs: "

    if purpose:
        prompt = prompt+ "\n" + f"purpose of the mail is {purpose}, "
    if contextual_background:
        prompt = prompt+ "\n" + f"consider the contextual background {contextual_background}, "
    if call_to_action:
        prompt = prompt + "\n"+ f"with an expectation of {call_to_action} "
    if additional_details:
        prompt = prompt+ "\n" + f"incorporate the following additional details: {additional_details}. "

    if priority_level:
        prompt = prompt + "\n"+f"The mail is of {priority_level} priority. "

    if closing_remarks:
        prompt = prompt+ "\n" + f"Incorporate the closing remarks {closing_remarks}. "

    if rephrase == "Y":
        prompt = prompt+ "\n" + " rephrase the subject"

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
    # output = str(chat_completion.choices[0].message.content).split(":")[1:]
    # print(type(output))
    # print(output)

    # print(chat_completion.choices[0].message.content)
    return(chat_completion.choices[0].message.content)
#text = generate_email("confirm details", "100", "Require Contact Details","Y" ,"client", "formal", "SPOC, AI, contract, project, deadline, payment", "Had a conversation with VP last week regarding an AI project on contract basis. Looking for further updates","meeting","","High","")
def generate_bus_pro(business_intro, proposal_objective, num_words, scope_of_work, project_phases, expected_outcomes, innovative_approaches, technologies_used, target_audience,budget_info,timeline,benefits, closing_remarks):
    prompt = f"Generate an business proposal of maximum {num_words} words, given the following inputs: "
    if business_intro:
        prompt = prompt+ "\n" + f"Our business details are {business_intro}, "
    if proposal_objective:
        prompt = prompt+ "\n" + f"and the purpose of this proposal is {proposal_objective}, "
    if scope_of_work:
        prompt = prompt + "\n"+ f"Define the scope of work as {scope_of_work}. "
    if project_phases:
        prompt = prompt+ "\n" + f"The project will be done in the following phases: {project_phases}. "
    if expected_outcomes:
        prompt = prompt + "\n"+f"Reprise the client of these expected outcomes: {expected_outcomes}. "
    if innovative_approaches:
        prompt = prompt + "\n"+f"Mention our following innovative approach: {innovative_approaches}, "
    if technologies_used:
        prompt = prompt + "\n"+f"and following technologies_used: {technologies_used}. "
    if budget_info:
        prompt = prompt + "\n"+f"Incorporate this budget_info: {budget_info}. "
    if target_audience:
        prompt = prompt + "\n"+f"Bear in mind that the target_audience is: {target_audience}. "
    if timeline:
        prompt = prompt + "\n"+f"The timelines we hope to stick to is : {timeline}. "
    if benefits:
        prompt = prompt + "\n"+f"Incorporate into the proposal the following benefits : {benefits}. "
    if closing_remarks:
        prompt = prompt+ "\n" + f"Incorporate the following closing remarks {closing_remarks}. "

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

def generate_offer_letter(company_details,num_words, candidate_name, position_title, department, supervisor, status,location,
                          start_date, compensation, benefits, work_hours, duration,terms, acceptance_deadline,
                          contact_info, documents_needed, closing_remarks):
    prompt = f"Generate an offer letter of maximum {num_words} words, given the following inputs: "
    if company_details:
        prompt = prompt+ "\n" + f"Our business details are {company_details}, "
    if candidate_name:
        prompt = prompt+ "\n" + f"Candidate name is {candidate_name}, "
    if position_title:
        prompt = prompt + "\n"+ f"for the position of {position_title}, "
    if department:
        prompt = prompt+ "\n" + f"in the department: {department}, "
    if supervisor:
        prompt = prompt + "\n"+f"under the supervisor: {supervisor}. "
    if status:
        prompt = prompt + "\n"+f"as a {status} employee. "
    if location:
        prompt = prompt + "\n"+f"Expected to work from: {location}. "
    if start_date:
        prompt = prompt + "\n"+f"Candidate to join on {start_date}. "
    if compensation:
        prompt = prompt + "\n"+f"Candidate will be given a compensation of: {compensation}. "
    if benefits:
        prompt = prompt + "\n"+f"Added to the compensation there will be following benefits : {benefits}. "
    if work_hours:
        prompt = prompt + "\n"+f"Expected working hours : {work_hours}. "
    if duration:
        prompt = prompt + "\n"+f"for a duration of: {duration}. "
    if terms:
        prompt = prompt + "\n"+f"Following are the terms of offer: {terms}. "
    if acceptance_deadline:
        prompt = prompt + "\n"+f"the last day for accepting the offer is: {acceptance_deadline}. "
    if contact_info:
        prompt = prompt + "\n"+f"In case of any queries contact : {contact_info}. "
    if documents_needed:
        prompt = prompt + "\n"+f"Following documents to be produced on the day of joining: {documents_needed}. "

    if closing_remarks:
        prompt = prompt+ "\n" + f"Incorporate the following closing remarks in the offer letter {closing_remarks}. "

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


def generate_content(company_info, content_purpose, desired_action, topic_details, keywords, audience_profile, format_structure, num_words, seo_keywords, references):
    prompt = f"Generate content of maximum {num_words} words, given the following inputs: "
    if company_info:
        prompt = prompt+ "\n" + f"Our business details are {company_info}, "
    if content_purpose:
        prompt = prompt+ "\n" + f"Purpose of writing this content is {content_purpose}, "
    if desired_action:
        prompt = prompt + "\n"+ f"Action desired from the audience is {desired_action}, "
    if topic_details:
        prompt = prompt+ "\n" + f"Topic details: {topic_details}, "
    if keywords:
        prompt = prompt + "\n"+f"Some keywords to keep in mind: {keywords}. "
    if audience_profile:
        prompt = prompt + "\n"+f"Profile of audience {audience_profile}. "
    if format_structure:
        prompt = prompt + "\n"+f"Format structure desired is: {format_structure}. "
    if seo_keywords:
        prompt = prompt + "\n"+f"SEO keywords: {seo_keywords}. "
    if references:
        prompt = prompt + "\n"+f"Site these references: {references}. "
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

def  generate_sales_script(company_details,num_words,  product_descriptions, features_benefits, pricing_info, promotions, target_audience, sales_objectives, tone_style,
            competitive_advantage, testimonials, compliance, tech_integration ):
    prompt = f"Generate a sales script of maximum {num_words} words, given the following inputs: "
    if company_details:
        prompt = prompt+ "\n" + f"Our business details are {company_details}, "
    if product_descriptions:
        prompt = prompt+ "\n" + f"Product may be described as {product_descriptions}, "
    if features_benefits:
        prompt = prompt + "\n"+ f"These are the features and benefits: {features_benefits}, "
    if pricing_info:
        prompt = prompt+ "\n" + f"Pricing Info: {pricing_info}, "
    if promotions:
        prompt = prompt + "\n"+f"Following promotions exist: {promotions}. "
    if target_audience:
        prompt = prompt + "\n"+f"Target audience is: {target_audience}. "
    if sales_objectives:
        prompt = prompt + "\n"+f"The sales objectives are: {sales_objectives}. "
    if tone_style:
        prompt = prompt + "\n"+f"Tone and style to be maintained: {tone_style}. "
    if competitive_advantage:
        prompt = prompt + "\n"+f"The competitive advantage that we have is: {competitive_advantage}. "
    if testimonials:
        prompt = prompt + "\n"+f"Mention these testimonials : {testimonials}. "
    if compliance:
        prompt = prompt + "\n"+f"Our compliance standards : {compliance}. "
    if tech_integration:
        prompt = prompt + "\n"+f"Tech integration in our company: {tech_integration}. "

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


import requests
BHASHINI_API_KEY = "3388a67633-6908-40d4-b18e-a36dcece199c"   #"151f3b0918-e63a-47fe-b13e-a5ae20ba0b3f"
BHASHINI_USER_ID = "1cdd78392233477bbaaf08c1453ab342"     #"9c22ef04e702419c9655cb0f30be7143"

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
