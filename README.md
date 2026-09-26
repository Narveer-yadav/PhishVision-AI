# 🛡️ PhishVision AI

PhishVision AI is a web-based phishing detection tool that checks a website from two different angles:

- **Screenshot analysis** using a fine-tuned Vision Transformer (ViT)
- **URL threat analysis** using VirusTotal threat intelligence

You can provide a website screenshot, a URL, or both. The application then presents the available findings and a simple security assessment.

---

## Why I Built This

Phishing websites often try to look like legitimate websites by copying their layout, branding, login pages, and other visual elements.

Traditional URL-based checks can miss some of these visual clues. PhishVision AI explores another approach by using the appearance of a website as an additional signal.

The project combines visual classification with URL-based threat intelligence to give users more context before interacting with a website.

---

## Features

- Upload a website screenshot for visual analysis
- Detect phishing-related visual patterns using a Vision Transformer
- Display phishing and legitimate probabilities
- Enter a website URL for threat-intelligence analysis
- Check URLs using VirusTotal
- Show malicious and suspicious detections
- Analyze screenshot and URL together
- Simple Streamlit web interface
- Hugging Face-hosted machine learning model

---

## How It Works

```text
                Website Screenshot
                        │
                        ▼
                Vision Transformer
                        │
                        ▼
                Visual Classification
                        │
                        ▼
                  Visual Findings


                    Website URL
                        │
                        ▼
                   VirusTotal API
                        │
                        ▼
                Threat Intelligence
                        │
                        ▼
                   URL Findings


              ┌─────────────────────┐
              │ Security Assessment │
              └─────────────────────┘


The two analysis methods work independently.

If both a screenshot and URL are provided, the application combines the available findings into a security assessment.

📸 Application Screenshots
Home Page

Screenshot Analysis

Screenshot Analysis Result

URL Analysis

URL Analysis Result

Combined Analysis

Combined Security Result


Machine Learning Model

PhishVision AI uses a pretrained Vision Transformer that was fine-tuned for phishing website screenshot classification.

Base Model
google/vit-base-patch16-224

The original pretrained model was adapted for two classes:
0 → Legitimate
1 → Phishing

Website screenshots are processed at:

224 × 224 pixels
Fine-Tuned Model

The trained model is hosted on Hugging Face:

Model:
https://huggingface.co/narveeryadav/PhishVision-AI

The Streamlit application automatically downloads the model from Hugging Face when it is required.


Dataset

The model was trained using a phishing website screenshot dataset containing:

Class	Images
Legitimate	1,147
Phishing	550
Total	1,697

The dataset was divided into training, validation, and testing sets.

Dataset Split
Split	Legitimate	Phishing	Total
Training	917	     440	      1,357
Validation	114	      55          169
Testing	    116       55	     171

The dataset is used for academic and experimental purposes. Refer to the original dataset source for its licensing and usage terms.

Model Performance

The final model was evaluated on the held-out test set.

Metric	Result
Accuracy	73.68%
Precision	58.33%
Recall	63.64%
F1 Score	60.87%

Confusion Matrix
Actual / Predicted	Legitimate	Phishing
Legitimate	91	25
Phishing	20	35

These results represent performance on the project's test dataset. They should not be interpreted as real-world phishing detection accuracy.

URL Threat Analysis

For URL analysis, the application uses the VirusTotal API.

The URL is submitted to VirusTotal and the returned engine results are used to provide a simple interpretation.

The application checks indicators such as:

Malicious detections
Suspicious detections
Harmless detections
Undetected results
Number of engines reporting results

The application categorizes the result as:

Potential Threat
Suspicious
No Significant Threat Detected

VirusTotal results depend on the available threat-intelligence engines and should not be treated as an absolute guarantee that a website is safe or malicious.

Technology Stack
Machine Learning
Python
PyTorch
Hugging Face Transformers
Vision Transformer (ViT)
Scikit-learn
Pillow


Web Application
Streamlit
Threat Intelligence
VirusTotal API
REST API
Python Requests
Configuration
python-dotenv
.env environment variables
Model Hosting
Hugging Face
Source Code
Git
GitHub

Project Structure
PhishVision-AI/
│
├── app.py
├── virustotal.py
├── requirements.txt
├── README.md
├── .gitignore
├── .env.example
│
├── Screenshots/
│   ├── Home.png
│   ├── combined-analysis.png
│   ├── combined-result.png
│   ├── screenshot-analysis.png
│   ├── screenshot-analysis-result.png
│   ├── url-analysis.png
│   └── url-analysis-result.png
│
└── training/
    └── ...

 The trained model is not stored in this repository. It is hosted separately on Hugging Face.

The dataset and virtual environment are also excluded from the repository


Getting Started
1. Clone the Repository
git clone https://github.com/narveeryadav/PhishVision-AI.git
cd PhishVision-AI
2. Create a Virtual Environment
Windows
python -m venv venv

Activate it:

.\venv\Scripts\Activate.ps1


3. Install Dependencies
pip install -r requirements.txt
4. Configure VirusTotal

Create a .env file in the project root:

VT_API_KEY=your_virustotal_api_key_here

An example configuration is provided in:

.env.example

Do not commit your actual .env file or API key to GitHub.


5. Run the Application
python -m streamlit run app.py

The application will open in your browser.

On the first run, the trained model will be downloaded from Hugging Face and cached locally

Usage
Screenshot Analysis
Open the application.
Upload a website screenshot.
Click Analyze Website.
Review the visual classification and probabilities.
URL Analysis
Enter a website URL.
Click Analyze Website.
Review the VirusTotal threat indicators.
Combined Analysis

You can provide both a screenshot and URL.

The application will show:

Visual analysis
URL threat analysis
Combined security assessment

Limitations

PhishVision AI is an academic and experimental project.

Some important limitations are:

Screenshot classification can produce false positives and false negatives.
A legitimate-looking website can still be malicious.
A phishing website can change its appearance and avoid visual detection.
The model was trained on a relatively small screenshot dataset.
VirusTotal results depend on the detections available from its security engines.
URL analysis does not guarantee that a website is safe.
The current system does not perform complete webpage or browser-level analysis.
The model's test-set performance does not represent detection performance on every website on the internet.

For these reasons, the results should be treated as security indicators rather than definitive verdicts.

Security and Privacy

The VirusTotal API key is loaded from an environment variable and is not stored in the source code.

Do not commit:

.env

or any API keys, tokens, passwords, or other credentials to the repository.

The trained machine learning model is hosted separately on Hugging Face.


Disclaimer

PhishVision AI is intended for educational, research, and security-awareness purposes.

It should not be used as the sole method for deciding whether a website is safe.

Always verify the domain, certificate, source of the link, and other security indicators before entering sensitive information.


Author

Narveer

GitHub

https://github.com/Narveer-yadav

Hugging Face Model

https://huggingface.co/narveeryadav/PhishVision-AI