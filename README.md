# PhishLock AI

![PhishLock AI Logo](https://raw.githubusercontent.com/yourusername/phishlock-ai/main/src/frontend/static/images/shield.svg)

## AI-Powered Phishing Detection through Ensemble Learning

PhishLock AI is an open-source solution that leverages multiple AI approaches to detect sophisticated phishing attacks with high accuracy and complete transparency. Developed for the SANS AI Cybersecurity Hackathon, this project addresses one of cybersecurity's most persistent challenges.

**[Live Demo](https://phishlock-ai.onrender.com/)** | **[Video Demonstration](https://www.youtube.com/watch?v=GoOuU6V23BE)**

[![PhishLock AI Demo](https://img.youtube.com/vi/GoOuU6V23BE/0.jpg)](https://www.youtube.com/watch?v=GoOuU6V23BE)

## Key Features

### Multi-Layered Detection Engine
- **Behavioral Analysis**: Identifies manipulation tactics like urgency, fear, and authority
- **URL & Domain Inspection**: Detects suspicious links, domains, and typosquatting attempts
- **Language Model Integration**: Uses advanced AI to catch sophisticated phishing content
- **Visual Logo Detection**: Identifies brand impersonation in HTML emails
- **Knowledge Base Matching**: Compares against known legitimate templates and phishing patterns

### Explainable AI
- **Transparent Decisions**: Clear explanations of all detection factors
- **Multiple Detail Levels**: Basic, detailed, and technical explanations for different users
- **Confidence Metrics**: Precise confidence scoring for each decision component

### Privacy-Preserving Design
- **Local Processing**: Analysis happens entirely on-server
- **No Message Storage**: Content is analyzed in memory without persistent storage
- **Anonymized Metrics**: Only aggregated statistics are maintained for performance tracking

## Technical Implementation

### Architecture
PhishLock AI uses a modern, modular architecture:

```
├── src/
│   ├── api/             # API endpoints and core analysis logic
│   ├── frontend/        # Web interface components
│   └── ml/              # Machine learning and analysis modules
│       ├── behavioral_analyzer.py  # Pattern-based detection
│       ├── url_extractor.py        # URL and domain analysis
│       ├── llm_analyzer.py         # Language model integration
│       ├── logo_detector.py        # Visual brand detection
│       ├── rag_analyzer.py         # Template matching
│       ├── knowledge_base.py       # Phishing pattern database
│       ├── fabric_integration.py   # Open-source framework integration
│       └── ethics_module.py        # Explanation generation
├── server.py            # FastAPI server implementation
└── requirements.txt     # Project dependencies
```

### Technology Stack
- **Backend**: Python with FastAPI
- **Frontend**: HTML/CSS/JavaScript with Bootstrap
- **AI Components**: Custom ML modules with optional LLM integration
- **Visualization**: Chart.js for interactive dashboard metrics
- **Deployment**: Render.com cloud platform

### Open-Source Integrations
- **Fabric Framework**: Advanced pattern recognition
- **Concierge Support**: Autonomous security actions (optional)
- **MIT License**: Complete freedom to use and modify

## Performance Metrics

Our testing shows that PhishLock AI significantly outperforms traditional rule-based detection:

- **Overall Accuracy**: 94%
- **False Positive Rate**: 7%
- **False Negative Rate**: 5%
- **Average Analysis Time**: 1.2 seconds per message

## Getting Started

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/phishlock-ai.git
cd phishlock-ai

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn server:app --reload
```

### Configuration
Create a `.env` file in the project root with the following optional variables:

```
# Optional LLM API Keys (if using language model integration)
OPENAI_API_KEY=your_key_here
# Or
ANTHROPIC_API_KEY=your_key_here

# Feature Flags
ENABLE_LLM=true  # Enable/disable language model integration
ENABLE_RAG=true  # Enable/disable RAG template matching
ENABLE_FABRIC=false  # Enable/disable Fabric framework
```

## Deployment

PhishLock AI is deployed on Render.com. To deploy your own instance:

1. Fork the repository to your GitHub account
2. Create a new Web Service on Render.com
3. Connect to your GitHub repository
4. Configure the build as follows:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. Add any environment variables needed
6. Deploy the service

## Usage

1. Access the web interface at `http://localhost:8000` (or your deployed URL)
2. Input the email details (sender, subject, content, optional HTML)
3. Click "Analyze Message"
4. Review the analysis results and recommended actions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- SANS Institute for hosting the AI Cybersecurity Hackathon
- The open-source community for providing the tools and frameworks used in this project
- All contributors who helped shape and improve PhishLock AI

## Contact

- GitHub Issues: Preferred method for bug reports and feature requests
- Email: cmandikonza@css.edu (replace with your actual contact)

---

*PhishLock AI: Detecting today's threats with tomorrow's technology*
