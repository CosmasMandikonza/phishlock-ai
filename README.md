# PhishLock AI 🛡️

![PhishLock AI](docs/images/banner.png)

## Advanced Open-Source Phishing Detection with AI

PhishLock AI is a cutting-edge, open-source phishing detection system that combines Large Language Models, behavioral analysis, and threat intelligence to identify even the most sophisticated phishing attempts.

**Created for the SANS AI Cybersecurity Hackathon**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![Last Commit](https://img.shields.io/github/last-commit/yourusername/phishlock-ai)

## 🔐 Key Features

- **RAG-Enhanced Analysis**: Combines AI language models with a knowledge base of phishing patterns using Retrieval-Augmented Generation
- **Behavioral Analysis**: Detects manipulation tactics like urgency, fear, and authority common in phishing
- **Advanced URL Analysis**: Identifies suspicious domains, typosquatting, and URL obfuscation
- **Brand Impersonation Detection**: Recognizes when trusted brands are being imitated
- **Interactive Dashboard**: Clear visualization of threats with detailed explanations
- **Educational Recommendations**: Provides actionable security guidance

## 🚀 Demo & Screenshots

![Demo](docs/images/demo.gif)

<details>
<summary>View Screenshots</summary>

| Analysis Screen | Dashboard |
|----------|----------|
| ![Analysis](docs/images/analysis-screen.png) | ![Dashboard](docs/images/dashboard.png) |

</details>

## 📋 Installation

### Prerequisites

- Python 3.9+
- OpenAI API key

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishlock-ai.git
   cd phishlock-ai
   ```

2. Create a `.env` file with your OpenAI API key:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```

3. Build and run with Docker Compose:
   ```bash
   docker-compose up --build
   ```

4. Access the application at http://localhost:8000

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishlock-ai.git
   cd phishlock-ai
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file with your OpenAI API key:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```

5. Run the application:
   ```bash
   uvicorn src.api.main:app --reload
   ```

6. Access the application at http://localhost:8000

## 🧠 How It Works

PhishLock AI uses a multi-layered approach to detect phishing:

1. **Knowledge Base**: A repository of phishing patterns, tactics, and indicators
2. **RAG-Enhanced LLM Analysis**: Uses OpenAI's GPT models with Retrieval-Augmented Generation
3. **Behavioral Analysis**: Detects psychological manipulation tactics
4. **URL & Domain Analysis**: Checks for suspicious domains and deceptive links
5. **Brand Impersonation Detection**: Identifies attempts to mimic trusted organizations

The system combines these signals to provide comprehensive analysis with high accuracy.

## 📊 Architecture

![Architecture](docs/images/architecture.png)

PhishLock AI is built with a modular architecture:

- **Frontend**: Interactive UI built with HTML, CSS, JavaScript, and Chart.js
- **API Layer**: FastAPI backend handling requests and responses
- **Analysis Engine**: Core detection components
  - RAG Analyzer
  - Behavioral Analyzer
  - URL Extractor & Analyzer
  - Logo Detector
- **Knowledge Base**: Repository of phishing patterns and indicators

## 📚 API Reference

### Analyze Message

```
POST /api/analyze
```

Request body:
```json
{
  "content": "Hello, please click this link to verify your account: http://example.com",
  "sender": "service@example.com",
  "subject": "Account verification needed",
  "html_content": "<optional HTML content>"
}
```

Response:
```json
{
  "is_suspicious": true,
  "confidence": 0.85,
  "reasons": ["Suspicious URL detected", "Urgency tactics detected"],
  "tactics_used": ["urgency", "authority"],
  "suspicious_domains": [{
    "domain": "example.com",
    "url": "http://example.com",
    "score": 0.7,
    "indicators": ["Suspicious TLD", "Brand mismatch"]
  }],
  "extracted_urls": ["http://example.com"],
  "impersonated_brand": "Microsoft",
  "analysis_time": 0.534,
  "recommendation": "This appears to be a phishing attempt impersonating Microsoft. Verify through official channels before taking any action."
}
```

### System Statistics

```
GET /api/stats
```

Response:
```json
{
  "total_analyses": 157,
  "phishing_detected": 73,
  "clean_messages": 84,
  "phishing_percentage": 46.5,
  "average_confidence": 0.78,
  "average_analysis_time": 0.62,
  "top_tactics": [["urgency", 45], ["fear", 32], ["reward", 15]],
  "top_impersonated_brands": [["Microsoft", 28], ["PayPal", 15], ["Amazon", 12]],
  "system_status": "operational"
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [OpenAI](https://openai.com/) for the GPT models
- [FastAPI](https://fastapi.tiangolo.com/) for the API framework
- [Chart.js](https://www.chartjs.org/) for the visualizations
- [Bootstrap](https://getbootstrap.com/) for the UI components
- [SANS Institute](https://www.sans.org/) for hosting the AI Cybersecurity Hackathon
