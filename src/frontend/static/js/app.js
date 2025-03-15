/**
 * PhishLock AI - Main Application Script with Sidebar Support
 */

// Global variables
let currentAnalysisId = null;
let gaugeChart = null;
let detectionChart = null;
let systemStats = null;

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize UI components
    initializeUI();
    
    // Set up event listeners
    setupEventListeners();
    
    // Fetch system stats
    fetchSystemStats();
    
    // Set up sidebar functionality
    setupSidebar();
});

/**
 * Initialize UI components
 */
function initializeUI() {
    // Setup HTML toggle
    const hasHtmlCheckbox = document.getElementById('has-html');
    const htmlInput = document.querySelector('.html-input');
    
    if (hasHtmlCheckbox && htmlInput) {
        hasHtmlCheckbox.addEventListener('change', function() {
            htmlInput.style.display = this.checked ? 'block' : 'none';
        });
    }
    
    // Initialize gauge chart
    initializeGaugeChart();
    
    // Initialize detection chart
    initializeDetectionChart();
}
// Add to app.js, right after the detectionChart initialization

// Initialize timeline chart
function initializeTimelineChart() {
    const timelineCtx = document.getElementById('timeline-chart');
    
    if (!timelineCtx) return;
    
    // Generate some sample data for demonstration
    const labels = [];
    const phishingData = [];
    const legitimateData = [];
    
    // Create data for the last 24 hours
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
        const hour = new Date(now);
        hour.setHours(now.getHours() - i);
        labels.push(hour.getHours() + ':00');
        
        // Generate random data for demo
        phishingData.push(Math.floor(Math.random() * 10));
        legitimateData.push(Math.floor(Math.random() * 15));
    }
    
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Phishing Detected',
                    data: phishingData,
                    borderColor: '#ff4757',
                    backgroundColor: 'rgba(255, 71, 87, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Legitimate Messages',
                    data: legitimateData,
                    borderColor: '#2ed573',
                    backgroundColor: 'rgba(46, 213, 115, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Message Analysis Activity (Last 24 Hours)'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Messages'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            }
        }
    });
}
/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Phishing form submission
    const phishingForm = document.getElementById('phishing-form');
    if (phishingForm) {
        phishingForm.addEventListener('submit', function(e) {
            e.preventDefault();
            analyzeMessage();
        });
    }
    
    // View technical details button
    const viewDetailsBtn = document.getElementById('view-details-btn');
    if (viewDetailsBtn) {
        viewDetailsBtn.addEventListener('click', function() {
            const technicalDetails = document.getElementById('technical-details');
            if (technicalDetails.style.display === 'none') {
                technicalDetails.style.display = 'block';
                viewDetailsBtn.innerHTML = '<i class="bi bi-arrow-up-circle"></i> Hide Technical Details';
            } else {
                technicalDetails.style.display = 'none';
                viewDetailsBtn.innerHTML = '<i class="bi bi-arrow-down-circle"></i> View Technical Details';
            }
        });
    }
    
    // Feedback buttons
    const feedbackCorrect = document.getElementById('feedback-correct');
    const feedbackIncorrect = document.getElementById('feedback-incorrect');
    
    if (feedbackCorrect) {
        feedbackCorrect.addEventListener('click', function() {
            submitFeedback(true);
        });
    }
    
    if (feedbackIncorrect) {
        feedbackIncorrect.addEventListener('click', function() {
            submitFeedback(false);
        });
    }
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 70,
                    behavior: 'smooth'
                });
                
                // On mobile, close the sidebar after navigation
                if (window.innerWidth < 768) {
                    const sidebar = document.querySelector('.sidebar');
                    if (sidebar) {
                        sidebar.classList.remove('active');
                    }
                }
                
                // Update active link
                updateActiveLink(this);
            }
        });
    });
}

/**
 * Initialize the gauge chart for confidence visualization
 */
function initializeGaugeChart() {
    const gaugeCtx = document.getElementById('gauge-chart');
    
    if (!gaugeCtx) return;
    
    gaugeChart = new Chart(gaugeCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: [
                    '#4d61fc',
                    '#e9ecef'
                ],
                borderWidth: 0
            }]
        },
        options: {
            circumference: 180,
            rotation: 270,
            cutout: '70%',
            plugins: {
                tooltip: {
                    enabled: false
                },
                legend: {
                    display: false
                }
            },
            responsive: true,
            maintainAspectRatio: true
        }
    });
}

/**
 * Initialize the detection chart for system stats
 */
function initializeDetectionChart() {
    const detectionCtx = document.getElementById('detection-chart');
    
    if (!detectionCtx) return;
    
    detectionChart = new Chart(detectionCtx, {
        type: 'pie',
        data: {
            labels: ['Phishing', 'Legitimate'],
            datasets: [{
                data: [0, 0],
                backgroundColor: [
                    '#ff4757',
                    '#2ed573'
                ],
                borderWidth: 0
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            responsive: true,
            maintainAspectRatio: true
        }
    });
}

/**
 * Set up sidebar functionality
 */
function setupSidebar() {
    // Mobile menu toggle
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.querySelector('.sidebar');
    
    if (menuToggle && sidebar) {
        menuToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }
    
    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', function(e) {
        if (window.innerWidth < 768 && 
            sidebar && 
            sidebar.classList.contains('active') && 
            !sidebar.contains(e.target) && 
            e.target !== menuToggle) {
            sidebar.classList.remove('active');
        }
    });
    
    // Set active link based on scroll position
    window.addEventListener('scroll', debounce(function() {
        setActiveMenuItemOnScroll();
    }, 100));
    
    // Initially set active link based on location
    setActiveMenuItemOnScroll();
}

/**
 * Update active link in sidebar
 * @param {Element} clickedLink - The link that was clicked
 */
function updateActiveLink(clickedLink) {
    // Remove active class from all links
    document.querySelectorAll('.sidebar-menu li').forEach(item => {
        item.classList.remove('active');
    });
    
    // Add active class to the parent li of the clicked link
    if (clickedLink) {
        clickedLink.closest('li').classList.add('active');
    }
}

/**
 * Set active menu item based on scroll position
 */
function setActiveMenuItemOnScroll() {
    // Get all sections
    const sections = document.querySelectorAll('section[id]');
    let currentSection = '';
    
    // Find which section is in view
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.offsetHeight;
        
        if (window.scrollY >= sectionTop - 100 && window.scrollY < sectionTop + sectionHeight - 100) {
            currentSection = section.getAttribute('id');
        }
    });
    
    // Update active link in menu
    if (currentSection) {
        document.querySelectorAll('.sidebar-menu li').forEach(item => {
            item.classList.remove('active');
            
            const link = item.querySelector(`a[href="#${currentSection}"]`);
            if (link) {
                item.classList.add('active');
            }
        });
    }
}

/**
 * Debounce function for scroll events
 * @param {Function} func - Function to debounce
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, delay) {
    let timeout;
    
    return function() {
        const context = this;
        const args = arguments;
        
        clearTimeout(timeout);
        
        timeout = setTimeout(function() {
            func.apply(context, args);
        }, delay);
    };
}

/**
 * Analyze message using the API
 */
async function analyzeMessage() {
    // Get form values
    const sender = document.getElementById('sender').value;
    const subject = document.getElementById('subject').value;
    const content = document.getElementById('content').value;
    const hasHtml = document.getElementById('has-html').checked;
    const htmlContent = hasHtml ? document.getElementById('html-content').value : null;
    
    // Show loading state
    setLoadingState(true);
    
    try {
        // Prepare request data
        const requestData = {
            sender: sender,
            subject: subject,
            content: content,
            html_content: htmlContent
        };
        
        // Call the API
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            throw new Error(`Error: ${response.status}`);
        }
        
        // Parse the response
        const result = await response.json();
        
        // Display the result
        displayAnalysisResult(result);
        
        // Generate a random analysis ID
        currentAnalysisId = `analysis_${Date.now()}`;
        
        // Refresh system stats
        fetchSystemStats();
        
    } catch (error) {
        console.error('Error analyzing message:', error);
        displayError(error.message || 'An error occurred while analyzing the message');
    } finally {
        setLoadingState(false);
    }
}

/**
 * Display the analysis result
 * @param {Object} result - The analysis result from the API
 */
function displayAnalysisResult(result) {
    // Show result container, hide placeholder
    document.getElementById('result-container').style.display = 'block';
    document.getElementById('analysis-placeholder').style.display = 'none';
    
    // Update header and verdict
    const resultHeader = document.getElementById('result-header');
    const verdictContainer = document.getElementById('verdict-container');
    const verdict = document.getElementById('verdict');
    const confidence = document.getElementById('confidence');
    
    // Set classes based on result
    resultHeader.className = 'card-header';
    verdictContainer.className = '';
    
    if (result.is_suspicious) {
        resultHeader.classList.add('suspicious');
        verdictContainer.classList.add('suspicious');
        verdict.textContent = '⚠️ Phishing Detected';
    } else {
        resultHeader.classList.add('safe');
        verdictContainer.classList.add('safe');
        verdict.textContent = '✅ Message Appears Safe';
    }
    
    // Update confidence
    confidence.textContent = `Confidence: ${Math.round(result.confidence * 100)}%`;
    
    // Update gauge chart
    updateGaugeChart(result.confidence);
    
    // Update reasons
    const reasonsList = document.getElementById('result-reasons');
    reasonsList.innerHTML = '';
    
    result.reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
    });
    
    // Update brand information
    const brandsSection = document.getElementById('brands-section');
    const brandInfo = document.getElementById('brand-info');
    
    if (result.impersonated_brand) {
        brandsSection.style.display = 'block';
        brandInfo.innerHTML = `
            <div class="alert alert-warning">
                <i class="bi bi-exclamation-triangle"></i> 
                Detected impersonation of <strong>${result.impersonated_brand}</strong>
            </div>
            <p>This message appears to be impersonating ${result.impersonated_brand}. 
            Always verify the sender's email address and check for official communication channels.</p>
        `;
    } else {
        brandsSection.style.display = 'none';
    }
    
    // Update tactics information
    const tacticsSection = document.getElementById('tactics-section');
    const tacticsInfo = document.getElementById('tactics-info');
    
    if (result.tactics_used && result.tactics_used.length > 0) {
        tacticsSection.style.display = 'block';
        
        let tacticsHtml = '<div class="row">';
        
        const tacticDescriptions = {
            'urgency': 'Creates a false sense of urgency to force hasty decisions',
            'fear': 'Uses fear to manipulate victims into taking action',
            'authority': 'Impersonates authority figures to increase compliance',
            'reward': 'Exploits desire for rewards or financial gain',
            'curiosity': 'Exploits natural curiosity to encourage clicking',
            'scarcity': 'Creates impression of limited availability to drive action',
            'social_proof': 'Leverages human tendency to follow what others do',
            'pressure': 'Applies pressure to make victims act without thinking',
            'generic_greeting': 'Uses generic greetings instead of personalized ones',
            'poor_grammar': 'Contains language errors often seen in phishing'
        };
        
        result.tactics_used.forEach(tactic => {
            const formattedTactic = tactic.replace(/_/g, ' ');
            const description = tacticDescriptions[tactic] || 'Manipulation tactic commonly used in phishing';
            
            tacticsHtml += `
                <div class="col-md-6 mb-2">
                    <div class="p-2 border rounded">
                        <h6>${formattedTactic.charAt(0).toUpperCase() + formattedTactic.slice(1)}</h6>
                        <small>${description}</small>
                    </div>
                </div>
            `;
        });
        
        tacticsHtml += '</div>';
        tacticsInfo.innerHTML = tacticsHtml;
    } else {
        tacticsSection.style.display = 'none';
    }
    
    // Update URLs information
    const urlsSection = document.getElementById('urls-section');
    const urlsInfo = document.getElementById('urls-info');
    
    if (result.suspicious_domains && result.suspicious_domains.length > 0) {
        urlsSection.style.display = 'block';
        
        let urlsHtml = '<div class="alert alert-danger mb-3"><i class="bi bi-exclamation-triangle"></i> Suspicious domains detected</div>';
        urlsHtml += '<div class="table-responsive"><table class="table table-sm"><thead><tr><th>Domain</th><th>Risk</th><th>Issues</th></tr></thead><tbody>';
        
        result.suspicious_domains.forEach(domain => {
            const riskLevel = domain.score > 0.7 ? 'High' : 'Medium';
            const riskClass = domain.score > 0.7 ? 'danger' : 'warning';
            
            urlsHtml += `
                <tr>
                    <td><code>${domain.domain || domain.url}</code></td>
                    <td><span class="badge bg-${riskClass}">${riskLevel}</span></td>
                    <td>${domain.indicators ? domain.indicators.join(', ') : 'Unknown'}</td>
                </tr>
            `;
        });
        
        urlsHtml += '</tbody></table></div>';
        
        if (result.extracted_urls && result.extracted_urls.length > 0) {
            urlsHtml += '<h6 class="mt-3">All URLs Found:</h6><ul class="list-group">';
            
            result.extracted_urls.forEach(url => {
                urlsHtml += `<li class="list-group-item"><small><code>${url}</code></small></li>`;
            });
            
            urlsHtml += '</ul>';
        }
        
        urlsInfo.innerHTML = urlsHtml;
    } else if (result.extracted_urls && result.extracted_urls.length > 0) {
        urlsSection.style.display = 'block';
        
        let urlsHtml = '<h6>URLs Found:</h6><ul class="list-group">';
        
        result.extracted_urls.forEach(url => {
            urlsHtml += `<li class="list-group-item"><small><code>${url}</code></small></li>`;
        });
        
        urlsHtml += '</ul>';
        urlsInfo.innerHTML = urlsHtml;
    } else {
        urlsSection.style.display = 'none';
    }
    
    // Update recommendation
    const recommendation = document.getElementById('recommendation');
    recommendation.innerHTML = result.recommendation || 'No specific recommendations available.';
    
    if (result.is_suspicious) {
        recommendation.classList.add('suspicious');
        recommendation.classList.remove('safe', 'warning');
    } else {
        recommendation.classList.add('safe');
        recommendation.classList.remove('suspicious', 'warning');
    }
    
    // Update technical details
    const technicalDetailsContent = document.getElementById('technical-details-content');
    technicalDetailsContent.innerHTML = '';
    
    if (result.technical_details) {
        // Add rows for each technical detail
        Object.entries(result.technical_details).forEach(([key, value]) => {
            // Format the key
            const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            // Format the value based on type
            let formattedValue = '';
            
            if (typeof value === 'number') {
                formattedValue = value.toFixed(2);
            } else if (Array.isArray(value)) {
                formattedValue = value.join(', ');
            } else if (typeof value === 'object' && value !== null) {
                formattedValue = JSON.stringify(value, null, 2);
            } else {
                formattedValue = String(value);
            }
            
            // Create row
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${formattedKey}</strong></td>
                <td>${formattedValue}</td>
            `;
            
            technicalDetailsContent.appendChild(row);
        });
    }
    
    // Add analysis time
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><strong>Analysis Time</strong></td>
        <td>${result.analysis_time ? result.analysis_time.toFixed(2) + ' seconds' : 'Unknown'}</td>
    `;
    
    technicalDetailsContent.appendChild(row);
}

/**
 * Update the gauge chart with the confidence value
 * @param {number} confidence - Confidence value (0-1)
 */
function updateGaugeChart(confidence) {
    if (gaugeChart) {
        // Calculate the percentage value
        const percentage = confidence * 100;
        
        // Update chart data
        gaugeChart.data.datasets[0].data = [percentage, 100 - percentage];
        
        // Update chart colors based on confidence
        let color = '#4d61fc'; // Default blue
        
        if (confidence > 0.7) {
            color = '#ff4757'; // Red for high risk
        } else if (confidence > 0.4) {
            color = '#ffa502'; // Orange for medium risk
        } else if (confidence < 0.3) {
            color = '#2ed573'; // Green for low risk
        }
        
        gaugeChart.data.datasets[0].backgroundColor[0] = color;
        
        // Update the chart
        gaugeChart.update();
    }
}

/**
 * Fetch system statistics
 */
async function fetchSystemStats() {
    try {
        const response = await fetch('/api/stats');
        
        if (!response.ok) {
            throw new Error(`Error: ${response.status}`);
        }
        
        // Parse the response
        const stats = await response.json();
        
        // Save stats globally
        systemStats = stats;
        
        // Update the stats UI
        updateStatsUI(stats);
        
    } catch (error) {
        console.error('Error fetching system stats:', error);
    }
}

/**
 * Update the stats UI with the fetched data
 * @param {Object} stats - System statistics
 */
function updateStatsUI(stats) {
    // Update metrics
    if (document.getElementById('total-analyses')) {
        document.getElementById('total-analyses').textContent = stats.total_analyses || 0;
    }
    
    if (document.getElementById('phishing-percentage')) {
        document.getElementById('phishing-percentage').textContent = `${(stats.phishing_percentage || 0).toFixed(1)}%`;
    }
    
    if (document.getElementById('avg-time')) {
        document.getElementById('avg-time').textContent = `${(stats.average_analysis_time || 0).toFixed(2)}s`;
    }
    
    // Update detection chart
    if (detectionChart && stats.phishing_detected !== undefined && stats.clean_messages !== undefined) {
        detectionChart.data.datasets[0].data = [
            stats.phishing_detected,
            stats.clean_messages
        ];
        
        detectionChart.update();
    }
    
    // Update top tactics
    if (document.getElementById('top-tactics') && stats.top_tactics) {
        const topTacticsElem = document.getElementById('top-tactics');
        topTacticsElem.innerHTML = '';
        
        stats.top_tactics.forEach(([tactic, count]) => {
            const formattedTactic = tactic.replace(/_/g, ' ');
            const percentage = (count / stats.total_analyses * 100).toFixed(1);
            
            const progressHtml = `
                <div class="progress-container">
                    <div class="progress-label">
                        <span>${formattedTactic.charAt(0).toUpperCase() + formattedTactic.slice(1)}</span>
                        <span>${percentage}%</span>
                    </div>
                    <div class="progress">
                        <div class="progress-bar bg-primary" role="progressbar" style="width: ${percentage}%" 
                             aria-valuenow="${percentage}" aria-valuemin="0" aria-valuemax="100"></div>
                    </div>
                </div>
            `;
            
            topTacticsElem.innerHTML += progressHtml;
        });
    }
    
    // Update top brands
    if (document.getElementById('top-brands') && stats.top_impersonated_brands) {
        const topBrandsElem = document.getElementById('top-brands');
        topBrandsElem.innerHTML = '';
        
        stats.top_impersonated_brands.forEach(([brand, count]) => {
            const percentage = (count / stats.total_analyses * 100).toFixed(1);
            
            const progressHtml = `
                <div class="progress-container">
                    <div class="progress-label">
                        <span>${brand}</span>
                        <span>${percentage}%</span>
                    </div>
                    <div class="progress">
                        <div class="progress-bar bg-danger" role="progressbar" style="width: ${percentage}%" 
                             aria-valuenow="${percentage}" aria-valuemin="0" aria-valuemax="100"></div>
                    </div>
                </div>
            `;
            
            topBrandsElem.innerHTML += progressHtml;
        });
    }
}

/**
 * Submit feedback on the analysis result
 * @param {boolean} isCorrect - Whether the analysis was correct
 */
async function submitFeedback(isCorrect) {
    if (!currentAnalysisId) return;
    
    try {
        // Prepare feedback data
        const feedbackData = {
            analysis_id: currentAnalysisId,
            is_correct: isCorrect,
            comments: null
        };
        
        // Call the API
        const response = await fetch('/api/feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(feedbackData)
        });
        
        if (!response.ok) {
            throw new Error(`Error: ${response.status}`);
        }
        
        // Show success message
        alert('Thank you for your feedback!');
        
    } catch (error) {
        console.error('Error submitting feedback:', error);
        alert('Error submitting feedback: ' + error.message);
    }
}

/**
 * Set the loading state of the form
 * @param {boolean} isLoading - Whether the form is loading
 */
function setLoadingState(isLoading) {
    const submitBtn = document.querySelector('#phishing-form button[type="submit"]');
    const submitText = document.getElementById('submit-text');
    const loadingSpinner = document.getElementById('loading-spinner');
    
    if (isLoading) {
        submitBtn.disabled = true;
        submitText.textContent = 'Analyzing...';
        loadingSpinner.style.display = 'inline-block';
    } else {
        submitBtn.disabled = false;
        submitText.textContent = 'Analyze Message';
        loadingSpinner.style.display = 'none';
    }
}

/**
 * Display an error message
 * @param {string} message - Error message to display
 */
function displayError(message) {
    alert('Error: ' + message);
}