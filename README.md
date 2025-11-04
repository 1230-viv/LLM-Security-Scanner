# 🛡️ AI-Powered Intrusion Detection System (IDS)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> A machine learning-based network intrusion detection system that detects and classifies cyber attacks in real-time.

---

## 📋 Overview

This AI-Powered IDS uses machine learning to detect network attacks (DoS, DDoS, Probe, R2L, U2R) in real-time. It features:

- 🤖 **Multiple ML Models**: Random Forest, XGBoost, Neural Networks
- 📊 **Live Dashboard**: Real-time threat visualization and alerts
- 🔍 **Anomaly Detection**: Identifies unknown threats
- ⚡ **Real-time Processing**: Continuous network traffic analysis
- 📈 **High Accuracy**: 99%+ detection rate

---

## 🏗️ Architecture

```
Network Traffic → Data Preprocessing → ML Models → Threat Detection → Dashboard
                                    ↓
                              (RF, XGBoost, NN)
```

---

## 📁 Project Structure

```
AI-Powered-Intrusion-Detection-System/
├── src/                           # Source code
│   ├── data_preprocessing.py      # Data cleaning & feature engineering
│   ├── model_training.py          # ML model training
│   ├── real_time_detector.py      # Live threat detection
│   └── utils.py                   # Helper functions
├── dashboard/                     # Web interface
│   ├── app.py                     # Flask backend
│   ├── static/                    # CSS, JS, images
│   └── templates/                 # HTML pages
├── notebooks/                     # Jupyter notebooks
│   ├── 01_EDA.ipynb              # Data exploration
│   ├── 02_Model_Training.ipynb   # Model experiments
│   └── 03_Evaluation.ipynb       # Performance analysis
├── data/                          # Datasets
├── models/                        # Trained models
├── config/                        # Configuration files
└── tests/                         # Unit tests
```

---

## 🚀 Implementation Plan

### **Phase 1: Data Preparation** (Week 1-2)

**Dataset**: Use NSL-KDD Dataset (125K training samples, 41 features)
- Download from: https://www.unb.ca/cic/datasets/nsl.html

**Steps**:
1. Load and explore dataset
2. Handle missing values and outliers
3. Encode categorical features
4. Normalize numerical features
5. Split into train/test sets (80/20)

---

### **Phase 2: Model Development** (Week 3-4)

**Train Multiple Models**:

1. **Random Forest**
   - Best for feature importance
   - Fast training, high accuracy
   
2. **XGBoost**
   - Highest accuracy (99%+)
   - Handles imbalanced data well
   
3. **Neural Network (MLP)**
   - Deep learning approach
   - Good for complex patterns

**Evaluation Metrics**:
- Accuracy, Precision, Recall, F1-Score
- Confusion Matrix
- ROC-AUC Curve

---

### **Phase 3: Real-Time Detection** (Week 5)

**Components**:
1. **Traffic Capture**: Use Scapy/PyShark to capture packets
2. **Feature Extraction**: Extract 41 features from packets
3. **Prediction**: Load trained model and classify traffic
4. **Alerting**: Generate alerts for detected threats

---

### **Phase 4: Dashboard** (Week 6-7)

**Flask Web Application**:

**Features**:
- Live traffic monitoring
- Alert notifications
- Attack statistics (pie/line charts)
- Model performance metrics
- Threat logs with filtering

**Tech Stack**:
- Backend: Flask + Flask-SocketIO
- Frontend: HTML, CSS, JavaScript
- Charts: Chart.js
- Database: SQLite

---

### **Phase 5: Testing & Deployment** (Week 8-9)

1. **Testing**: Unit tests, integration tests
2. **Docker**: Containerize application
3. **Documentation**: Usage guide, API docs
4. **GitHub**: Clean repo with badges

---

## 🛠️ Technologies

- **ML/DL**: Scikit-learn, XGBoost, TensorFlow
- **Data**: Pandas, NumPy
- **Web**: Flask, Chart.js, Bootstrap
- **Network**: Scapy, PyShark
- **DevOps**: Docker, pytest

---

## 💻 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/yourusername/AI-Powered-Intrusion-Detection-System.git
cd AI-Powered-Intrusion-Detection-System

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### 2. Prepare Data

```bash
# Download NSL-KDD dataset and place in data/raw/
python src/data_preprocessing.py
```

### 3. Train Models

```bash
# Train all models
python src/model_training.py

# Or train specific model
python src/model_training.py --model xgboost
```

### 4. Run Dashboard

```bash
python dashboard/app.py
# Access at http://localhost:5000
```

### 5. Real-Time Detection

```bash
# Start detector
python src/real_time_detector.py --interface eth0
```

---

## 📊 Expected Results

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 98.5% | 98.3% | 98.1% | 98.2% |
| XGBoost | 99.1% | 99.0% | 98.8% | 98.9% |
| Neural Network | 98.8% | 98.6% | 98.4% | 98.5% |

**Attack Detection Rates**:
- DoS: 99.2%
- Probe: 98.7%
- R2L: 96.5%
- U2R: 95.8%

---

## 📈 Datasets

### NSL-KDD (Recommended)
- Size: 125K samples
- Features: 41
- Classes: Normal, DoS, Probe, R2L, U2R
- [Download](https://www.unb.ca/cic/datasets/nsl.html)

### Alternatives
- **CICIDS2017**: Modern attacks (2.8M records)
- **UNSW-NB15**: Contemporary threats (2.5M records)

---

## 🎯 Key Features to Implement

### Core Modules
1. ✅ Data preprocessing pipeline
2. ✅ Multi-model training system
3. ✅ Real-time packet capture
4. ✅ Threat classification engine
5. ✅ Alert generation system

### Dashboard Features
1. ✅ Live traffic graph
2. ✅ Attack statistics (charts)
3. ✅ Recent alerts feed
4. ✅ Model performance display
5. ✅ Filterable threat logs

---

## 🐳 Docker Deployment

```bash
# Build image
docker build -t ids-system .

# Run container
docker run -p 5000:5000 ids-system

# Using docker-compose
docker-compose up -d
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file

---

## 🎓 Learning Resources

- [NSL-KDD Dataset Paper](https://ieeexplore.ieee.org)
- [Scikit-learn Documentation](https://scikit-learn.org/)
- [Flask Documentation](https://flask.palletsprojects.com/)

---

## ⭐ Show Your Support

Give a ⭐️ if this project helped you!

---

**Made with ❤️ for Cybersecurity**