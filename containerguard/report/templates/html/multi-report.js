/**
 * ContainerGuard Multi-Report JavaScript
 *
 * This script handles the additional interactive elements for multi-target reports:
 * - Tab switching between targets
 * - Target-specific filtering
 * - Enhanced chart functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tab functionality
    initTabs();

    // Initialize target cards click functionality
    initTargetCards();
});

/**
 * Initialize tab switching functionality
 */
function initTabs() {
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            // Get tab ID
            const tabId = this.getAttribute('data-tab');

            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(t => {
                t.classList.remove('active');
            });

            // Remove active class from all tab contents
            document.querySelectorAll('.tab-content').forEach(tc => {
                tc.classList.remove('active');
            });

            // Add active class to clicked tab
            this.classList.add('active');

            // Add active class to corresponding tab content
            document.getElementById(tabId).classList.add('active');
        });
    });
}

/**
 * Initialize target cards click functionality to switch to target tab
 */
function initTargetCards() {
    const targetCards = document.querySelectorAll('.target-card');

    targetCards.forEach((card, index) => {
        card.addEventListener('click', function() {
            // Get target tab (index + 2 because we have "All" and "Critical" tabs first)
            const tabIndex = index + 2;
            const tab = document.querySelector(`.tab[data-tab="target-${tabIndex}"]`);

            if (tab) {
                tab.click();

                // Scroll to findings section
                document.getElementById('findings').scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
}

/**
 * Initialize filter buttons for the findings table
 */
function initFilters() {
    const filterButtons = document.querySelectorAll('.filter-button');

    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filterValue = this.getAttribute('data-filter');

            // Remove active class from all filter buttons
            document.querySelectorAll('.filter-button').forEach(btn => {
                btn.classList.remove('active');
            });

            // Add active class to clicked button
            this.classList.add('active');

            // Show/hide rows based on filter
            const rows = document.querySelectorAll('.findings-table tbody tr');

            rows.forEach(row => {
                const severity = row.querySelector('.severity-badge').textContent.trim().toLowerCase();

                if (filterValue === 'all' || severity === filterValue) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    });
}

/**
 * Generate a per-target severity chart
 *
 * @param {string} targetId - Target identifier
 * @param {Array} severities - List of severity counts: [critical, high, medium, low, info]
 */
function createTargetSeverityChart(targetId, severities) {
    const chartData = [{
        x: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        y: severities,
        type: 'bar',
        marker: {
            color: ['#ff3a33', '#ff8800', '#ffcc00', '#88cc14', '#00bbff']
        }
    }];

    const layout = {
        title: `Findings by Severity for ${targetId}`,
        height: 300,
        margin: { t: 50, b: 80, l: 50, r: 50 },
        xaxis: {
            tickangle: -45
        },
        yaxis: {
            title: 'Count'
        }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    const chartElement = document.getElementById(`target-${targetId}-chart`);
    if (chartElement) {
        Plotly.newPlot(chartElement, chartData, layout, config);
    }
}

/**
 * Create a comparison chart for all targets
 */
function createTargetComparisonChart() {
    if (!window.targetData || Object.keys(window.targetData).length === 0) {
        return;
    }

    const targets = Object.keys(window.targetData);
    const criticalCounts = targets.map(target => window.targetData[target].critical);
    const highCounts = targets.map(target => window.targetData[target].high);
    const mediumCounts = targets.map(target => window.targetData[target].medium);

    const chartData = [
        {
            x: targets,
            y: criticalCounts,
            name: 'Critical',
            type: 'bar',
            marker: { color: '#ff3a33' }
        },
        {
            x: targets,
            y: highCounts,
            name: 'High',
            type: 'bar',
            marker: { color: '#ff8800' }
        },
        {
            x: targets,
            y: mediumCounts,
            name: 'Medium',
            type: 'bar',
            marker: { color: '#ffcc00' }
        }
    ];

    const layout = {
        title: 'Comparison of Critical, High, and Medium Findings',
        barmode: 'stack',
        height: 400,
        margin: { t: 50, b: 100, l: 50, r: 50 },
        xaxis: {
            tickangle: -45
        },
        yaxis: {
            title: 'Count'
        }
    };

    const config = {
        responsive: true
    };

    const chartElement = document.getElementById('targetComparisonChart');
    if (chartElement) {
        Plotly.newPlot(chartElement, chartData, layout, config);
    }
}

/**
 * Generate a heatmap visualization of findings across targets
 */
function createFindingsHeatmap() {
    if (!window.findingsData || !window.targetData) {
        return;
    }

    const targets = Object.keys(window.targetData);
    const findingsMap = {};

    // Count findings by ID for each target
    Object.keys(window.findingsData).forEach(findingId => {
        findingsMap[findingId] = {};

        targets.forEach(target => {
            findingsMap[findingId][target] = window.findingsData[findingId].targets[target] || 0;
        });
    });

    // Convert to heatmap format
    const xValues = targets;
    const yValues = Object.keys(findingsMap);
    const zValues = yValues.map(finding =>
        targets.map(target => findingsMap[finding][target])
    );

    const chartData = [{
        x: xValues,
        y: yValues,
        z: zValues,
        type: 'heatmap',
        colorscale: [
            [0, '#ffffff'],
            [0.2, '#e6f7ff'],
            [0.4, '#88cc14'],
            [0.6, '#ffcc00'],
            [0.8, '#ff8800'],
            [1, '#ff3a33']
        ]
    }];

    const layout = {
        title: 'Findings Heatmap Across Targets',
        height: 600,
        margin: { t: 50, b: 100, l: 200, r: 50 },
        xaxis: {
            tickangle: -45
        }
    };

    const config = {
        responsive: true
    };

    const chartElement = document.getElementById('findingsHeatmap');
    if (chartElement) {
        Plotly.newPlot(chartElement, chartData, layout, config);
    }
}