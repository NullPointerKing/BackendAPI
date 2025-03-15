import joblib
import numpy as np
import re
import os
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from flask_cors import CORS
from groq import Groq

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins (for testing)  

# Securely fetch API key from environment variables
api_key = os.getenv("")
# if not api_key:
#     raise ValueError("API key for Groq is missing! Set it using:\nexport GROQ_API_KEY='your_api_key_here'")

client = Groq(api_key="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")

# Load the trained model & scaler
# try:
#     model = joblib.load("phishing_model_best.pkl")
#     scaler = joblib.load("scaler.pkl")  # If you used feature scaling
# except FileNotFoundError:
#     raise FileNotFoundError("Model or scaler file is missing! Ensure 'phishing_model_best.pkl' and 'scaler.pkl' exist.")

# Feature extraction function
def extract_features(url):
    parsed_url = urlparse(url)
    features = {
        "url_length": len(url),
        "num_subdomains": len(parsed_url.netloc.split(".")) - 1,
        "num_special_chars": len(re.findall(r"[@_!#$%^&*()<>?/\|}{~:]", url)),
        "is_https": 1 if parsed_url.scheme == "https" else 0,
        "has_phishing_keyword": int(any(keyword in url.lower() for keyword in ["login", "banking", "secure", "verify", "account", "update", "paypal"]))
    }
    return np.array(list(features.values())).reshape(1, -1)

# Function to call Groq API
def call_groq(url):
    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a phishing link detector expert."},
                {"role": "user", "content": f"Is this a phishing link? Give me answer in either 'True' or 'False'. URL: {url}"}
                
            ],
            model="llama-3.3-70b-versatile"
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error in Groq API call: {str(e)}"

# Home route for form-based URL checking
# @app.route("/", methods=["GET", "POST"])
# def home():
#     if request.method == "POST":
#         url = request.form.get("url")
#         if not url:
#             return render_template("index.html", url=None, result="⚠️ No URL provided!")
        
#         features = extract_features(url)
#         features_scaled = scaler.transform(features)  
#         prediction = model.predict(features_scaled)[0]
#         result = "🛑 Phishing" if prediction == 1 else "✅ Legitimate"
        
#         return render_template("index.html", url=url, result=result)
    
#     return render_template("index.html", url=None, result=None)

# API Endpoint for external requests
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"error": "⚠️ No URL provided"}), 400
    
    groq_result = call_groq(url)  # Get response from Groq API
    features = extract_features(url)
    # features_scaled = scaler.transform(features)
    # prediction = model.predict(features_scaled)[0]
    # result = "🛑 Phishing" if prediction == 1 else "✅ Legitimate"
    
    return jsonify({
        "url": url,
        "result": groq_result,
        "status": "🔍 Analysis complete!"
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
