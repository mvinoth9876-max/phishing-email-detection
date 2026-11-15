
# 🔐 Phishing Email Detection System

An AI-Based Email Security Analyzer built using Python and Flask to identify suspicious email content and potentially malicious URLs.

## 🚀 Features

- Email sender format validation
- Suspicious keyword detection
- URL extraction and analysis
- HTTP and HTTPS security checks
- IP address URL detection
- Suspicious URL keyword detection
- Risk scoring (LOW, MEDIUM, HIGH)
- Interactive security dashboard
- Scan history management
- Downloadable security reports

## 🛠️ Technologies Used

- Python
- Flask
- HTML5
- CSS3
- JavaScript
- Scikit-learn
- Pandas
- BeautifulSoup
- Joblib

## 📂 Project Structure

```text
phishing-email-detection/
│
├── app.py
├── train.py
├── predict.py
├── email_analyzer.py
├── url_scanner.py
├── requirements.txt
│
├── dataset/
│   └── emails.csv
│
├── models/
│   ├── best_model.pkl
│   └── feature_names.pkl
│
├── templates/
│   └── index.html
│
└── README.md
```

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mvinoth9876-max/phishing-email-detection.git
```

### 2. Navigate to Project Folder

```bash
cd phishing-email-detection
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

### 5. Open in Browser

```text
http://127.0.0.1:5000/
```

## 🔍 How It Works

1. Enter the sender email address.
2. Enter the email subject and body.
3. The system checks suspicious keywords.
4. URLs are extracted and analyzed.
5. Security indicators are evaluated.
6. A risk score is calculated.
7. The dashboard displays the risk level.
8. Download the generated security report.

## 📊 Risk Classification

| Risk Level | Description |
|---|---|
| LOW | Few configured warning indicators |
| MEDIUM | Multiple suspicious indicators |
| HIGH | Strong suspicious indicators |

## 🤖 Machine Learning

The project includes a separately trained machine learning classifier using a word-frequency dataset.

The model training and prediction modules are provided separately from the current rule-based email and URL analyzer.

## ⚠️ Disclaimer

This project is developed for educational and cybersecurity learning purposes. It uses heuristic security checks and a dataset-based machine learning model. It does not guarantee detection of every phishing email or malicious URL.

## 👨‍💻 Developer

**Vinoth M**

BE Computer Science and Engineering – Cyber Security

GitHub: https://github.com/mvinoth9876-max
