# ThreatLens
![A promotional banner which says "ThreatLens"](https://github.com/robertrodrigu3z/ThreatLens/blob/main/static/images/ThreatLensPromotionalBanner.png?raw=true)
<p align="center">Developed by Carl Asojo, Robert Rodriguez, and Jason Klutse</p>

## Overview
ThreatLens serves as a Security Operations Centre (SOC) dashboard for cybersecurity-related events/attacks. Users can upload their security log data through a CSV file, for which the dashboard will then analyze the data and notify them of any issues or suspicious patterns. ThreatLens ranks these findings depending on severity and explains the most severe events using Google Gemini.


## Set-Up Instructions
This project requires Git and Python 3.9+, with a Google Gemini API key being optional as a requirement for AI functionality.

Move to the folder where you would like this project to be located, then run `git clone https://github.com/ca25acg/ThreatLens.git` and then `cd ThreatLens`. Then, install the required packages by running `py -m pip install -r requirements.txt` (Windows) or `python3 -m pip install -r requirements.txt` (macOS, Linux). If using the Google Gemini API key, run `cp .env.example .env` and then in .env, fill in your `GEMINI_API_KEY` (ex. `GEMINI_API_KEY=your_key_here`). You must use your own Gemini API key. Now, run the project using `py app.py` (Windows) or `python3 app.py` (macOS, Linux). You can then access http://127.0.0.1:5000 (or http://localhost:5000) to run this project locally.

## CSV Security Log Format
Your CSV requires 4 columns:
- `timestamp` (Uses ISO 8601)
- `event_type` (ex. `login_success`, `login_failed`)
- `username` (The username of the account involved)
- `ip_address` (Source IP of the account involved)

## How we built it
The front-end of this project uses Tailwind CSS and HTML, connecting to the back-end of this project developed using Python and Flask. Google Gemini API is sourced to explain information regarding the most severe cybersecurity events identified.

## What's next for ThreatLens
There's numerous components we'd like to implement into ThreatLens, including...
- More ways to upload security log data, rather than just CSV files (ex. JSON files, Linux logs)
- Better AI optimization (ex. Gemini can be considerably slow at times for AI responses)
- Implement Snowflake AI (some foundation has been set for Snowflake functionality)
- Consider further website elements (ex. swapping between light-mode and dark-mode website)
