import os
import time
import requests
import torch
import streamlit as st

from PIL import Image
from dotenv import load_dotenv
from transformers import ViTImageProcessor, ViTForImageClassification


# ============================================================
# CONFIG
# ============================================================

load_dotenv()

MODEL_DIR = "model"
VT_API_KEY = os.getenv("VT_API_KEY")

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishVision AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# SIMPLE STREAMLIT STYLING
# ============================================================

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1500px;
        padding-top: 2rem;
        padding-left: 4rem;
        padding-right: 4rem;
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    .main-title {
        font-size: 42px;
        font-weight: 800;
        text-align: center;
        margin-bottom: 5px;
    }

    .main-subtitle {
        text-align: center;
        color: #667085;
        font-size: 18px;
        margin-bottom: 30px;
    }

    .result-title {
        font-size: 28px;
        font-weight: 750;
        margin-top: 25px;
    }

    .small-text {
        color: #667085;
        font-size: 14px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ PhishVision AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="main-subtitle">Check a website before you trust it</div>',
    unsafe_allow_html=True
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    processor = ViTImageProcessor.from_pretrained(
        MODEL_DIR
    )

    model = ViTForImageClassification.from_pretrained(
        MODEL_DIR
    )

    model.to(DEVICE)
    model.eval()

    return processor, model


processor, model = load_model()


# ============================================================
# IMAGE ANALYSIS
# ============================================================

def analyze_image(image):

    inputs = processor(
        images=image,
        return_tensors="pt"
    )

    inputs = {
        key: value.to(DEVICE)
        for key, value in inputs.items()
    }

    with torch.no_grad():

        outputs = model(**inputs)

        probabilities = torch.softmax(
            outputs.logits,
            dim=1
        )

        prediction = torch.argmax(
            probabilities,
            dim=1
        ).item()

    legitimate = probabilities[0][0].item() * 100
    phishing = probabilities[0][1].item() * 100

    confidence = max(
        legitimate,
        phishing
    )

    if prediction == 1:

        if phishing >= 75:
            status = "Likely Phishing"
            message = (
                "The screenshot shows strong characteristics "
                "associated with phishing websites."
            )
            result_type = "danger"

        elif phishing >= 50:
            status = "Suspicious"
            message = (
                "The screenshot contains characteristics "
                "that may be associated with phishing."
            )
            result_type = "warning"

        else:
            status = "Potentially Suspicious"
            message = (
                "The model detected some unusual characteristics. "
                "Verify the website before continuing."
            )
            result_type = "warning"

    else:

        if legitimate >= 75:
            status = "Likely Safe"
            message = (
                "The visual model did not identify strong "
                "phishing characteristics."
            )
            result_type = "safe"

        elif legitimate >= 50:
            status = "Appears Safe"
            message = (
                "The screenshot appears relatively normal, "
                "but additional verification is recommended."
            )
            result_type = "safe"

        else:
            status = "Suspicious"
            message = (
                "The model could not confidently classify "
                "the screenshot as legitimate."
            )
            result_type = "warning"

    return {
        "status": status,
        "message": message,
        "type": result_type,
        "confidence": confidence,
        "legitimate": legitimate,
        "phishing": phishing
    }


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    if not VT_API_KEY:

        return {
            "error": "URL analysis is not configured."
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if response.status_code != 200:

            return {
                "error": "Unable to submit the URL for analysis."
            }

        data = response.json()

        analysis_id = data["data"]["id"]

        analysis_url = (
            f"{VT_BASE_URL}/analyses/{analysis_id}"
        )

        analysis_data = None

        for _ in range(10):

            response = requests.get(
                analysis_url,
                headers=headers,
                timeout=30
            )

            if response.status_code != 200:

                return {
                    "error": "Unable to retrieve URL analysis."
                }

            analysis_data = response.json()["data"]

            status = analysis_data["attributes"]["status"]

            if status == "completed":
                break

            time.sleep(2)

        else:

            return {
                "error": "URL analysis timed out."
            }

        stats = analysis_data["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = (
            malicious +
            suspicious +
            harmless +
            undetected
        )

        if malicious >= 2:

            status = "Potential Threat"
            result_type = "danger"

        elif malicious == 1 or suspicious >= 2:

            status = "Suspicious"
            result_type = "warning"

        else:

            status = "No Significant Threat Detected"
            result_type = "safe"

        return {
            "url": url,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "status": status,
            "type": result_type
        }

    except requests.RequestException:

        return {
            "error": "Network error while checking the URL."
        }

    except Exception:

        return {
            "error": "Something went wrong during URL analysis."
        }


# ============================================================
# INPUT SECTION
# ============================================================

st.subheader("Analyze a Website")

st.caption(
    "Upload a website screenshot, enter a URL, or provide both."
)

col1, col2 = st.columns(2)


# ============================================================
# SCREENSHOT
# ============================================================

with col1:

    st.markdown("### 📷 Website Screenshot")

    st.caption(
        "Upload a screenshot of the website you want to check."
    )

    uploaded_file = st.file_uploader(
        "Choose an image",
        type=["png", "jpg", "jpeg"]
    )


# ============================================================
# URL
# ============================================================

with col2:

    st.markdown("### 🌐 Website URL")

    st.caption(
        "Enter the complete website address."
    )

    url = st.text_input(
        "URL",
        placeholder="https://example.com"
    )


# ============================================================
# IMAGE PREVIEW
# ============================================================

image = None

if uploaded_file:

    try:

        image = Image.open(
            uploaded_file
        ).convert("RGB")

        st.markdown("### Screenshot Preview")

        st.image(
            image,
            width=700
        )

    except Exception:

        st.error(
            "Unable to read the uploaded image."
        )


# ============================================================
# ANALYZE BUTTON
# ============================================================

st.markdown("")

analyze_button = st.button(
    "🔎 Analyze Website",
    type="primary",
    use_container_width=True
)


# ============================================================
# START ANALYSIS
# ============================================================

if analyze_button:

    has_image = image is not None
    has_url = bool(url.strip())

    if not has_image and not has_url:

        st.warning(
            "Please upload a screenshot or enter a website URL."
        )

    else:

        image_result = None
        url_result = None


        # ====================================================
        # IMAGE
        # ====================================================

        if has_image:

            with st.spinner(
                "Analyzing the website screenshot..."
            ):

                image_result = analyze_image(
                    image
                )


        # ====================================================
        # URL
        # ====================================================

        if has_url:

            clean_url = url.strip()

            if not (
                clean_url.startswith("http://")
                or clean_url.startswith("https://")
            ):

                clean_url = "https://" + clean_url

            with st.spinner(
                "Checking the website URL..."
            ):

                url_result = analyze_url(
                    clean_url
                )


        # ====================================================
        # RESULTS
        # ====================================================

        st.markdown("---")

        st.markdown(
            '<div class="result-title">Security Results</div>',
            unsafe_allow_html=True
        )

        st.caption(
            "Review the available indicators before trusting the website."
        )


        # ====================================================
        # VISUAL RESULT
        # ====================================================

        if image_result:

            st.markdown("## 🖼️ Visual Analysis")

            if image_result["type"] == "danger":

                st.error(
                    f"⚠️ {image_result['status']}\n\n"
                    f"{image_result['message']}"
                )

            elif image_result["type"] == "warning":

                st.warning(
                    f"⚠️ {image_result['status']}\n\n"
                    f"{image_result['message']}"
                )

            else:

                st.success(
                    f"✓ {image_result['status']}\n\n"
                    f"{image_result['message']}"
                )


            metric1, metric2, metric3 = st.columns(3)

            with metric1:

                st.metric(
                    "Model Confidence",
                    f"{image_result['confidence']:.1f}%"
                )

            with metric2:

                st.metric(
                    "Phishing Probability",
                    f"{image_result['phishing']:.1f}%"
                )

            with metric3:

                st.metric(
                    "Legitimate Probability",
                    f"{image_result['legitimate']:.1f}%"
                )


            st.write("Phishing likelihood")

            st.progress(
                int(
                    min(
                        max(
                            image_result["phishing"],
                            0
                        ),
                        100
                    )
                )
            )


        # ====================================================
        # URL RESULT
        # ====================================================

        if url_result:

            st.markdown("## 🌐 URL Threat Analysis")

            if "error" in url_result:

                st.error(
                    url_result["error"]
                )

            else:

                st.code(
                    url_result["url"],
                    language=None
                )

                if url_result["type"] == "danger":

                    st.error(
                        f"⚠️ {url_result['status']}\n\n"
                        "Multiple security engines reported malicious activity."
                    )

                elif url_result["type"] == "warning":

                    st.warning(
                        f"⚠️ {url_result['status']}\n\n"
                        "Some security indicators require caution."
                    )

                else:

                    st.success(
                        f"✓ {url_result['status']}\n\n"
                        "No significant malicious detections were reported."
                    )


                metric1, metric2, metric3, metric4 = st.columns(4)

                with metric1:

                    st.metric(
                        "Malicious",
                        url_result["malicious"]
                    )

                with metric2:

                    st.metric(
                        "Suspicious",
                        url_result["suspicious"]
                    )

                with metric3:

                    st.metric(
                        "No Threat",
                        url_result["harmless"]
                    )

                with metric4:

                    st.metric(
                        "Engines Checked",
                        url_result["total"]
                    )


        # ====================================================
        # COMBINED ASSESSMENT
        # ====================================================

        if (
            image_result
            and url_result
            and "error" not in url_result
        ):

            st.markdown("---")

            st.markdown("## 🛡️ Security Assessment")

            visual_risk = (
                image_result["phishing"] >= 50
            )

            url_malicious = (
                url_result["malicious"] >= 1
            )

            url_suspicious = (
                url_result["suspicious"] >= 1
            )


            if visual_risk and url_malicious:

                st.error(
                    "⚠️ Multiple Risk Indicators\n\n"
                    "The screenshot analysis and URL analysis "
                    "both indicate potential risk. Avoid entering "
                    "passwords, payment details, OTPs, or other "
                    "sensitive information."
                )

            elif visual_risk and url_suspicious:

                st.warning(
                    "⚠️ Additional Verification Recommended\n\n"
                    "Both analyses produced warning indicators. "
                    "Verify the domain carefully before continuing."
                )

            elif url_malicious:

                st.error(
                    "⚠️ URL Risk Detected\n\n"
                    "The URL analysis detected malicious activity. "
                    "Treat the website with caution even if its "
                    "appearance looks normal."
                )

            elif visual_risk:

                st.warning(
                    "⚠️ Suspicious Website Appearance\n\n"
                    "The visual analysis detected phishing-like "
                    "characteristics. Verify the website address "
                    "before entering sensitive information."
                )

            else:

                st.success(
                    "✓ No Strong Risk Indicators\n\n"
                    "Neither analysis produced strong phishing "
                    "indicators. Continue to verify the domain "
                    "before sharing sensitive information."
                )


# ============================================================
# SAFETY INFORMATION
# ============================================================

st.markdown("---")

st.info(
    "🔐 **Stay Safe Online**\n\n"
    "Check the domain carefully before logging in. "
    "Avoid entering passwords, card details, OTPs, or other "
    "sensitive information on websites you do not trust. "
    "Security results are indicators and do not guarantee "
    "that a website is safe."
)


# ============================================================
# FOOTER
# ============================================================

st.caption(
    "PhishVision AI • Website security analysis"
)