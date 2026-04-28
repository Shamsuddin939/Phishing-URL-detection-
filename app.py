from flask import Flask, request, render_template
import numpy as np
import warnings
import pickle
from feature import FeatureExtraction
import logging

warnings.filterwarnings('ignore')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the model
try:
    with open("model.pkl", "rb") as f:
        gbc = pickle.load(f)
    logger.info(" Model loaded successfully!")
except FileNotFoundError:
    logger.error(" Model file 'model.pkl' not found!")
    gbc = None
except Exception as e:
    logger.error(f" Error loading model: {e}")
    gbc = None

app = Flask(__name__)

def analyze_website(url):
    """Improved analysis function with better phishing detection"""
    try:
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        logger.info(f" Analyzing URL: {url}")
        
        # Extract features
        obj = FeatureExtraction(url)
        features = obj.getFeaturesList()
        
        # Validate features
        if len(features) != 30:
            return {'error': f'Invalid features extracted. Expected 30, got {len(features)}'}
        
        # Prepare data for prediction
        x = np.array(features).reshape(1, 30)
        
        # Get predictions
        y_pred = gbc.predict(x)[0]
        y_proba = gbc.predict_proba(x)[0]
        
        legitimate_prob = y_proba[0]  # Probability of class -1 (Legitimate)
        phishing_prob = y_proba[1]    # Probability of class 1 (Phishing)
        
        #  ENHANCED PHISHING DETECTION LOGIC
        
        # 1. Primary detection using model probability
        if phishing_prob > 0.25:  # Lower threshold (25%) to catch more phishing sites
            status = "phishing"
            confidence = phishing_prob
        else:
            status = "legitimate" 
            confidence = legitimate_prob
        
        # 2. Feature-based override (more aggressive phishing detection)
        suspicious_features = sum(1 for f in features if f == 1)  # Count phishing indicators
        total_features = len(features)
        suspicion_ratio = suspicious_features / total_features
        
        # If high number of suspicious features, mark as phishing
        if suspicion_ratio > 0.4:  # 40% features indicate phishing
            status = "phishing"
            confidence = max(confidence, suspicion_ratio)
        
        # 3. Critical feature check (specific high-risk indicators)
        critical_features_indices = [0, 1, 2, 3, 4, 5]  # High-risk feature indices
        critical_suspicious = sum(1 for i in critical_features_indices if features[i] == 1)
        
        if critical_suspicious >= 3:  # If 3+ critical features are suspicious
            status = "phishing"
            confidence = 0.9  # High confidence
        
        # Calculate safety score
        safety_score = legitimate_prob * 100
        
        # Final prediction
        final_prediction = 1 if status == "phishing" else -1
        
        logger.info(f" Analysis Result: {status.upper()} (Phishing prob: {phishing_prob:.3f})")
        
        return {
            'status': status,
            'phishing_probability': round(phishing_prob * 100, 2),
            'safety_score': round(safety_score, 2),
            'suspicion_ratio': round(suspicion_ratio * 100, 2),
            'suspicious_features': suspicious_features,
            'total_features': total_features,
            'final_prediction': final_prediction,
            'confidence': round(confidence * 100, 2),
            'features': features  # For debugging
        }
        
    except Exception as e:
        logger.error(f" Error analyzing website: {e}")
        return {'error': f'Analysis failed: {str(e)}'}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        
        # Validate input
        if not url:
            return render_template("index.html", 
                                 result=None, 
                                 error="Please enter a URL",
                                 url="")
        
        if len(url) < 5:  # Basic URL length check
            return render_template("index.html",
                                 result=None,
                                 error="Please enter a valid URL",
                                 url="")
        
        # Check if model is loaded
        if gbc is None:
            return render_template("index.html",
                                 result=None,
                                 error="Phishing detection model is not available. Please try again later.",
                                 url=url)
        
        # Analyze the website
        result = analyze_website(url)
        
        if 'error' in result:
            return render_template("index.html",
                                 result=None,
                                 error=result['error'],
                                 url=url)
        
        return render_template("index.html",
                             result=result,
                             url=url,
                             error=None)
    
    # GET request - show empty form
    return render_template("index.html",
                         result=None,
                         error=None,
                         url="")

# Health check endpoint
@app.route("/health")
def health():
    return {
        "status": "healthy" if gbc is not None else "unhealthy",
        "model_loaded": gbc is not None
    }

# API endpoint for programmatic access
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """API endpoint for JSON responses"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return {"error": "URL parameter is required"}, 400
        
        url = data['url'].strip()
        if not url:
            return {"error": "URL cannot be empty"}, 400
        
        result = analyze_website(url)
        return result
        
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == "__main__":
    # Better configuration for production
    debug_mode = True  # Set to False in production
    host = '0.0.0.0'
    port = 5000
    
    logger.info(f" Starting Phishing Detection Server on port {port}")
    logger.info(f" Model status: {'LOADED' if gbc is not None else 'NOT LOADED'}")
    
    app.run(host=host, port=port, debug=debug_mode)