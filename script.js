/**
 * CVSS v3.1 Risk Calculator - JavaScript Module
 * Optimized for performance with separated concerns
 */

(function() {
    'use strict';

    // Configuration Constants
    const METRIC_VALUES = {
        av: { 
            network: 0.85, 
            adjacent: 0.62, 
            local: 0.55, 
            physical: 0.20 
        },
        ac: { 
            low: 0.77, 
            high: 0.44 
        },
        pr: { 
            none: 0.85,
            low: { unchanged: 0.62, changed: 0.68 },
            high: { unchanged: 0.27, changed: 0.50 }
        },
        ui: { 
            none: 0.85, 
            required: 0.62 
        },
        conf: { 
            none: 0.00, 
            low: 0.22, 
            high: 0.56 
        },
        integ: { 
            none: 0.00, 
            low: 0.22, 
            high: 0.56 
        },
        avail: { 
            none: 0.00, 
            low: 0.22, 
            high: 0.56 
        }
    };

    // Application State
    let currentSelections = {
        av: 'network',
        ac: 'low',
        pr: 'low',
        ui: 'none',
        scope: 'unchanged',
        conf: 'high',
        integ: 'none',
        avail: 'none'
    };

    // DOM Element Cache
    const elements = {};
    let isCalculating = false;

    /**
     * Cache DOM elements for better performance
     */
    function cacheElements() {
        elements.exploitabilityScore = document.getElementById('exploitabilityScore');
        elements.impactScore = document.getElementById('impactScore');
        elements.baseScore = document.getElementById('baseScore');
        elements.mainHeader = document.getElementById('mainHeader');
        elements.exploitabilityCard = document.getElementById('exploitabilityCard');
        elements.impactCard = document.getElementById('impactCard');
        elements.baseCard = document.getElementById('baseCard');
        elements.modal = document.getElementById('mysqlModal');
        elements.mysqlBtn = document.getElementById('mysqlBtn');
        elements.nvdBtn = document.getElementById('nvdBtn');
        elements.closeBtn = document.getElementById('closeBtn');
        elements.applyBtn = document.getElementById('applyBtn');
    }

    /**
     * Handle metric button selection
     * @param {HTMLElement} button - The clicked button
     */
    function selectMetric(button) {
        if (isCalculating) return;
        
        const metric = button.dataset.metric;
        const value = button.dataset.value;
        
        // Update button states
        const siblings = button.parentElement.querySelectorAll('.metric-btn');
        siblings.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Update state
        currentSelections[metric] = value;
        
        // Trigger calculation on next frame
        requestAnimationFrame(() => {
            calculateAndUpdate();
        });
    }

    /**
     * Calculate CVSS scores using current selections
     * @returns {Object} Object containing exploitability, impact, and baseScore
     */
    function calculateScores() {
        // Get exploitability values
        const av = METRIC_VALUES.av[currentSelections.av];
        const ac = METRIC_VALUES.ac[currentSelections.ac];
        const ui = METRIC_VALUES.ui[currentSelections.ui];
        
        // Handle PR value based on scope
        let pr;
        if (currentSelections.pr === 'none') {
            pr = METRIC_VALUES.pr.none;
        } else {
            pr = METRIC_VALUES.pr[currentSelections.pr][currentSelections.scope];
        }
        
        // Calculate exploitability
        const exploitability = 8.22 * av * ac * pr * ui;
        
        // Get impact values
        const c = METRIC_VALUES.conf[currentSelections.conf];
        const i = METRIC_VALUES.integ[currentSelections.integ];
        const a = METRIC_VALUES.avail[currentSelections.avail];
        
        // Calculate Impact Sub Score (ISS)
        const iss = 1 - (1 - c) * (1 - i) * (1 - a);
        
        // Calculate Impact based on scope
        let impact;
        if (currentSelections.scope === 'unchanged') {
            impact = 6.42 * iss;
        } else {
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        }
        
        // Calculate Base Score
        let baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else {
            if (currentSelections.scope === 'unchanged') {
                baseScore = Math.min(exploitability + impact, 10);
            } else {
                baseScore = Math.min(1.08 * (exploitability + impact), 10);
            }
        }
        
        // Apply CVSS rounding (round up to 1 decimal)
        baseScore = Math.ceil(baseScore * 10) / 10;
        
        return { exploitability, impact, baseScore };
    }

    /**
     * Update the display with calculated scores
     * @param {Object} scores - Calculated scores object
     */
    function updateDisplay(scores) {
        // Update score displays
        elements.exploitabilityScore.textContent = scores.exploitability.toFixed(2);
        elements.impactScore.textContent = scores.impact.toFixed(2);
        elements.baseScore.textContent = scores.baseScore.toFixed(1);
        
        // Update severity colors
        updateSeverityColors(scores.baseScore);
    }

    /**
     * Update UI colors based on severity level
     * @param {number} baseScore - The calculated base score
     */
    function updateSeverityColors(baseScore) {
        const severityClasses = ['severity-none', 'severity-low', 'severity-medium', 'severity-high', 'severity-critical'];
        const cards = [elements.mainHeader, elements.exploitabilityCard, elements.impactCard, elements.baseCard];
        
        // Remove existing severity classes
        cards.forEach(element => {
            severityClasses.forEach(cls => element.classList.remove(cls));
        });
        
        // Determine severity class
        let severityClass;
        if (baseScore === 0) {
            severityClass = 'severity-none';
        } else if (baseScore <= 3.9) {
            severityClass = 'severity-low';
        } else if (baseScore <= 6.9) {
            severityClass = 'severity-medium';
        } else if (baseScore <= 8.9) {
            severityClass = 'severity-high';
        } else {
            severityClass = 'severity-critical';
        }
        
        // Apply new severity class
        cards.forEach(element => element.classList.add(severityClass));
    }

    /**
     * Calculate scores and update display
     */
    function calculateAndUpdate() {
        if (isCalculating) return;
        
        isCalculating = true;
        
        try {
            const scores = calculateScores();
            updateDisplay(scores);
        } catch (error) {
            console.error('Error calculating scores:', error);
        } finally {
            isCalculating = false;
        }
    }

    /**
     * Show notification to user
     * @param {string} message - Notification message
     * @param {string} type - Notification type (info, success, error)
     */
    function showNotification(message, type = 'info') {
        // Remove existing notifications
        document.querySelectorAll('.notification').forEach(n => n.remove());

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <span>${message}</span>
            <button style="background:none;border:none;color:white;margin-left:10px;cursor:pointer;" onclick="this.parentElement.remove()">&times;</button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 3000);
    }

    /**
     * Apply MySQL scenario settings
     */
    function applyMySQLScenario() {
        const mysqlSettings = {
            av: 'network',
            ac: 'low',
            pr: 'low',
            ui: 'none',
            scope: 'unchanged',
            conf: 'high',
            integ: 'none',
            avail: 'none'
        };
        
        // Clear all active states
        document.querySelectorAll('.metric-btn.active').forEach(btn => btn.classList.remove('active'));
        
        // Apply MySQL settings
        Object.entries(mysqlSettings).forEach(([metric, value]) => {
            currentSelections[metric] = value;
            const button = document.querySelector(`[data-metric="${metric}"][data-value="${value}"]`);
            if (button) {
                button.classList.add('active');
            }
        });
        
        // Update calculations and close modal
        calculateAndUpdate();
        elements.modal.style.display = 'none';
        showNotification('MySQL scenario applied successfully!', 'success');
    }

    /**
     * Setup all event listeners
     */
    function setupEventListeners() {
        // Metric button clicks (using event delegation for better performance)
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('metric-btn')) {
                selectMetric(e.target);
            }
        });

        // MySQL scenario button
        elements.mysqlBtn.addEventListener('click', () => {
            elements.modal.style.display = 'block';
        });

        // Modal close button
        elements.closeBtn.addEventListener('click', () => {
            elements.modal.style.display = 'none';
        });

        // Apply MySQL settings button
        elements.applyBtn.addEventListener('click', applyMySQLScenario);

        // NVD reference button
        elements.nvdBtn.addEventListener('click', () => {
            window.open('https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator', '_blank');
        });

        // Close modal when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target === elements.modal) {
                elements.modal.style.display = 'none';
            }
        });

        // Keyboard event for modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && elements.modal.style.display === 'block') {
                elements.modal.style.display = 'none';
            }
        });
    }

    /**
     * Initialize the application
     */
    function init() {
        try {
            cacheElements();
            setupEventListeners();
            calculateAndUpdate();
            
            // Performance optimization: mark initialization complete
            document.documentElement.setAttribute('data-cvss-loaded', 'true');
            
        } catch (error) {
            console.error('Failed to initialize CVSS calculator:', error);
            showNotification('Error initializing calculator', 'error');
        }
    }

    /**
     * Public API for external access (if needed)
     */
    window.CVSSCalculator = {
        getCurrentSelections: () => ({ ...currentSelections }),
        calculateScores,
        applySettings: (settings) => {
            Object.assign(currentSelections, settings);
            calculateAndUpdate();
        }
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
