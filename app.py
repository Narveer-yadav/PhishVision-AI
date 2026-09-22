import os
import time
import requests
import streamlit as st
import torch

from PIL import Image
from transformers import ViTImageProcessor, ViTForImageClassification
from dotenv import load_dotenv


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="PhishVision AI",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>
    .block-container {
        max-width: 900px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1 {
        text-align: center;
    }

    .subtitle {
        text-align: center;
        color: #666;
        margin-bottom: 2rem;
    }

    .section-title {
        margin-top: 1.5rem;
        margin-bottom: 0.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# MODEL CONFIGURATION
# ============================================================

# Hugging Face model repository
MODEL_NAME = "narveeryadav/PhishVision-AI"

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


# ============================================================
# LOAD MODEL FROM HUGGING FACE
# ============================================================

@st.cache_resource
def load_model():

    processor = ViTImageProcessor.from_pretrained(
        MODEL_NAME
    )

    model = ViTForImageClassification.from_pretrained(
        MODEL_NAME
    )

    model.to(DEVICE)
    model.eval()

    return processor, model


# ============================================================
# VIRUSTOTAL CONFIGURATION
# ============================================================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


# ============================================================
# VIRUSTOTAL URL ANALYSIS
# ============================================================

def analyze_url(url):

    if not VT_API_KEY:
        return {
            "success": False,
            "message": "VirusTotal API key is not configured."
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        # Submit URL for analysis
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if response.status_code != 200:
            return {
                "success": False,
                "message": f"VirusTotal request failed ({response.status_code})."
            }

        data = response.json()

        analysis_id = data["data"]["id"]

        # Poll analysis result
        analysis_url = (
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        )

        stats = None

        for _ in range(10):

            analysis_response = requests.get(
                analysis_url,
                headers=headers,
                timeout=30
            )

            if analysis_response.status_code != 200:
                return {
                    "success": False,
                    "message": "Unable to retrieve VirusTotal analysis."
                }

            analysis_data = analysis_response.json()

            attributes = analysis_data["data"]["attributes"]

            status = attributes.get("status")

            if status == "completed":

                stats = attributes.get("stats", {})
                break

            time.sleep(2)

        if stats is None:
            return {
                "success": False,
                "message": "VirusTotal analysis timed out."
            }

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_engines = (
            malicious +
            suspicious +
            harmless +
            undetected
        )

        # Interpretation
        if malicious >= 2:

            assessment = "Potential Threat"

        elif malicious == 1 or suspicious >= 2:

            assessment = "Suspicious"

        else:

            assessment = "No Significant Threat Detected"

        return {
            "success": True,
            "assessment": assessment,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total_engines
        }

    except requests.RequestException:

        return {
            "success": False,
            "message": "Network error while contacting VirusTotal."
        }

    except Exception as e:

        return {
            "success": False,
            "message": f"URL analysis failed: {str(e)}"
        }


# ============================================================
# VISUAL ANALYSIS
# ============================================================

def analyze_image(image):

    processor, model = load_model()

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

        legitimate_probability = (
            probabilities[0][0].item() * 100
        )

        phishing_probability = (
            probabilities[0][1].item() * 100
        )

        confidence = (
            probabilities[0][prediction].item() * 100
        )

    return {
        "prediction": prediction,
        "legitimate_probability": legitimate_probability,
        "phishing_probability": phishing_probability,
        "confidence": confidence
    }


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ PhishVision AI")

st.markdown(
    '<div class="subtitle">Check a website before you trust it</div>',
    unsafe_allow_html=True
)


# ============================================================
# INPUT SECTION
# ============================================================

st.markdown(
    '<h3 class="section-title">🖼️ Website Screenshot</h3>',
    unsafe_allow_html=True
)

uploaded_file = st.file_uploader(
    "Upload a website screenshot",
    type=["png", "jpg", "jpeg"]
)


st.markdown(
    '<h3 class="section-title">🌐 Website URL</h3>',
    unsafe_allow_html=True
)

url = st.text_input(
    "Enter website URL",
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

        st.image(
            image,
            caption="Website Screenshot",
            use_container_width=True
        )

    except Exception:

        st.error(
            "Unable to read the uploaded image."
        )


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze_button = st.button(
    "🔍 Analyze Website",
    use_container_width=True
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not image and not url.strip():

        st.warning(
            "Please upload a screenshot or enter a website URL."
        )

        st.stop()

    visual_result = None
    url_result = None


    # ========================================================
    # VISUAL ANALYSIS
    # ========================================================

    if image:

        with st.spinner(
            "Analyzing website screenshot..."
        ):

            try:

                visual_result = analyze_image(
                    image
                )

            except Exception as e:

                st.error(
                    f"Visual analysis failed: {str(e)}"
                )


    # ========================================================
    # URL ANALYSIS
    # ========================================================

    if url.strip():

        with st.spinner(
            "Checking website URL..."
        ):

            url_result = analyze_url(
                url.strip()
            )


    # ========================================================
    # VISUAL RESULT
    # ========================================================

    if visual_result:

        st.markdown(
            '<h3 class="section-title">🖼️ Visual Analysis</h3>',
            unsafe_allow_html=True
        )

        phishing_probability = (
            visual_result["phishing_probability"]
        )

        legitimate_probability = (
            visual_result["legitimate_probability"]
        )

        confidence = visual_result["confidence"]

        prediction = visual_result["prediction"]


        # Classification
        if prediction == 1:

            if phishing_probability >= 80:

                st.error(
                    "🚨 Likely Phishing"
                )

            else:

                st.warning(
                    "⚠️ Suspicious"
                )

        else:

            if legitimate_probability >= 80:

                st.success(
                    "✅ Appears Safe"
                )

            else:

                st.warning(
                    "⚠️ Potentially Suspicious"
                )


        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Model Confidence",
                f"{confidence:.2f}%"
            )

        with col2:

            st.metric(
                "Phishing Probability",
                f"{phishing_probability:.2f}%"
            )

        with col3:

            st.metric(
                "Legitimate Probability",
                f"{legitimate_probability:.2f}%"
            )


        st.progress(
            min(phishing_probability / 100, 1.0)
        )


    # ========================================================
    # URL RESULT
    # ========================================================

    if url_result:

        st.markdown(
            '<h3 class="section-title">🌐 URL Threat Analysis</h3>',
            unsafe_allow_html=True
        )

        if url_result["success"]:

            assessment = url_result["assessment"]

            if assessment == "Potential Threat":

                st.error(
                    "🚨 Potential Threat"
                )

            elif assessment == "Suspicious":

                st.warning(
                    "⚠️ Suspicious"
                )

            else:

                st.success(
                    "✅ No Significant Threat Detected"
                )


            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.metric(
                    "Malicious",
                    url_result["malicious"]
                )

            with col2:

                st.metric(
                    "Suspicious",
                    url_result["suspicious"]
                )

            with col3:

                st.metric(
                    "No Threat",
                    url_result["harmless"]
                )

            with col4:

                st.metric(
                    "Engines Checked",
                    url_result["total"]
                )

        else:

            st.warning(
                url_result["message"]
            )


    # ========================================================
    # SECURITY ASSESSMENT
    # ========================================================

    if visual_result or (
        url_result and url_result["success"]
    ):

        st.markdown(
            '<h3 class="section-title">🛡️ Security Assessment</h3>',
            unsafe_allow_html=True
        )


        phishing_detected = False
        url_threat_detected = False


        if visual_result:

            if (
                visual_result["prediction"] == 1
                and visual_result["phishing_probability"] >= 60
            ):

                phishing_detected = True


        if url_result and url_result["success"]:

            if url_result["assessment"] in [
                "Potential Threat",
                "Suspicious"
            ]:

                url_threat_detected = True


        # Both indicate danger
        if phishing_detected and url_threat_detected:

            st.error(
                "🚨 Multiple security indicators detected. "
                "The website should be treated with caution."
            )

            st.write(
                "Avoid entering passwords, payment information, "
                "or other sensitive data."
            )


        # Visual model indicates phishing
        elif phishing_detected:

            st.warning(
                "⚠️ The screenshot analysis indicates "
                "potential phishing characteristics."
            )

            st.write(
                "Verify the website domain and avoid entering "
                "sensitive information until it is verified."
            )


        # URL indicates threat
        elif url_threat_detected:

            st.warning(
                "⚠️ Threat intelligence detected suspicious "
                "indicators associated with the URL."
            )

            st.write(
                "Avoid entering credentials or financial "
                "information on this website."
            )


        # No indicators
        else:

            st.success(
                "✅ No significant phishing indicators were "
                "detected by the available analyses."
            )

            st.write(
                "Always verify the website address before "
                "entering sensitive information."
            )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "PhishVision AI provides security indicators for analysis "
    "and should not be treated as a definitive security verdict."
)