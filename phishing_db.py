from flask_sqlalchemy import SQLAlchemy


# MySQL Database Configuration
# Replace 'root' and 'yourpassword' with your MySQL username and password
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:8600664504@localhost/phishing_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# URL History Table
class URLHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    prediction = db.Column(db.String(50))
    pro_safe = db.Column(db.Float)
    pro_phishing = db.Column(db.Float)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# Create tables if they don't exist
with app.app_context():
    db.create_all()

# Home / URL Prediction Route
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        pred_text = "It is {0:.2f}% safe to go".format(y_pro_phishing * 100)

        # Convert float64 to Python float before saving to MySQL
        record = URLHistory(
            url=url,
            prediction=str(y_pred),
            pro_safe=float(round(y_pro_non_phishing, 2)),
            pro_phishing=float(round(y_pro_phishing, 2))
        )
        db.session.add(record)
        db.session.commit()

        return render_template("index.html", xx=round(y_pro_non_phishing, 2), url=url)

    return render_template("index.html", xx=-1)

# URL History Route
@app.route("/history")
def history():
    urls = URLHistory.query.order_by(URLHistory.created_at.desc()).all()
    return render_template("history.html", urls=urls)

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
