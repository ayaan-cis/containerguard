/**
 * ContainerGuard Report JavaScript
 *
 * This script handles all interactive elements of the report including:
 * - Accordion functionality for findings
 * - Chart rendering using Plotly
 * - Responsiveness for mobile viewing
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize accordion functionality
    initAccordions();

    // Render charts if Plotly is available
    if (typeof Plotly !== 'undefined') {
        renderCharts();
    } else {
        console.warn("Plotly library not loaded. Charts will not be rendered.");
    }
});

/**
 * Initialize accordion functionality for findings
 */
function initAccordions() {
    const accordions = document.querySelectorAll('.accordion-header');

    accordions.forEach(accordion => {
        accordion.addEventListener('click', function() {
            // Toggle active class
            this.parentElement.classList.toggle('active');

            // Change toggle icon
            const toggle = this.querySelector('.accordion-toggle');
            toggle.textContent = this.parentElement.classList.contains('active') ? '▲' : '▼';
        });
    });

    // Open the first accordion by default if there are findings
    if (accordions.length > 0) {
        accordions[0].click();
    }
}

/**
 * Render charts using the data provided in the template
 */
function renderCharts() {
    // Render severity distribution chart if data exists
    const severityChartEl = document.getElementById('severityChart');
    if (severityChartEl && window.chartData && window.chartData.severityDistribution) {
        renderSeverityChart(severityChartEl, window.chartData.severityDistribution);
    }

    // Render category distribution chart if data exists
    const categoryChartEl = document.getElementById('categoryChart');
    if (categoryChartEl && window.chartData && window.chartData.categoryDistribution) {
        renderCategoryChart(categoryChartEl, window.chartData.categoryDistribution);
    }

    // Render top findings chart if data exists
    const topFindingsChartEl = document.getElementById('topFindingsChart');
    if (topFindingsChartEl && window.chartData && window.chartData.topFindings) {
        renderTopFindingsChart(topFindingsChartEl, window.chartData.topFindings);
    }
}

/**
 * Render the severity distribution pie chart
 *
 * @param {HTMLElement} element - The DOM element to render the chart in
 * @param {Object} data - The chart data
 */
function renderSeverityChart(element, data) {
    const chartData = [{
        labels: data.labels,
        values: data.values,
        type: 'pie',
        marker: {
            colors: [
                '#ff3a33',  // Critical
                '#ff8800',  // High
                '#ffcc00',  // Medium
                '#88cc14',  // Low
                '#00bbff'   // Info
            ]
        },
        textinfo: 'label+percent',
        hoverinfo: 'label+value+percent'
    }];

    const layout = {
        title: 'Findings by Severity',
        height: 400,
        margin: { t: 50, b: 50, l: 50, r: 50 },
        showlegend: false
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    Plotly.newPlot(element, chartData, layout, config);
}

/**
 * Render the category distribution bar chart
 *
 * @param {HTMLElement} element - The DOM element to render the chart in
 * @param {Object} data - The chart data
 */
function renderCategoryChart(element, data) {
    const chartData = [{
        x: data.labels,
        y: data.values,
        type: 'bar',
        marker: {
            color: '#0066cc'
        }
    }];

    const layout = {
        title: 'Findings by Category',
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
        responsive: true,
        displayModeBar: false
    };

    Plotly.newPlot(element, chartData, layout, config);
}

/**
 * Render the top findings horizontal bar chart
 *
 * @param {HTMLElement} element - The DOM element to render the chart in
 * @param {Object} data - The chart data
 */
function renderTopFindingsChart(element, data) {
    const chartData = [{
        x: data.values,
        y: data.labels,
        type: 'bar',
        orientation: 'h',
        marker: {
            color: '#0066cc'
        }
    }];

    const layout = {
        title: 'Top 10 Most Common Findings',
        height: 400,
        margin: { t: 50, b: 50, l: 200, r: 50 },
        xaxis: {
            title: 'Count'
        }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    Plotly.newPlot(element, chartData, layout, config);
}

/**
 * Update chart data in the template
 * This function is called by the Jinja2 template
 *
 * @param {Object} data - Chart data from the backend
 */
function setChartData(data) {
    window.chartData = data;
}