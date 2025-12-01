// Security Configuration
const SECURITY_CONFIG = {
    maxInputLength: 100,
    allowedChars: /^[a-zA-Z0-9\s\-_]+$/,
    apiEndpoint: '/api/clients',
    authEndpoint: '/api/auth',
    csrfTokenName: 'X-CSRF-Token'
};

// Application State
let clientData = [];
let filteredData = [];
let isAuthenticated = false;
let csrfToken = '';

// HTML Escaping Utility
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') {
        return unsafe;
    }
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Input Validation and Sanitization
function validateAndSanitizeInput(input, maxLength = SECURITY_CONFIG.maxInputLength) {
    if (typeof input !== 'string') {
        throw new Error('Invalid input type');
    }
    
    // Trim whitespace
    const sanitized = input.trim();
    
    // Check length
    if (sanitized.length > maxLength) {
        throw new Error(`Input exceeds maximum length of ${maxLength} characters`);
    }
    
    // Check allowed characters
    if (!SECURITY_CONFIG.allowedChars.test(sanitized)) {
        throw new Error('Input contains invalid characters');
    }
    
    return sanitized;
}

// Secure DOM Manipulation
function safeCreateElement(tag, textContent = '', attributes = {}) {
    const element = document.createElement(tag);
    
    if (textContent) {
        element.textContent = textContent;
    }
    
    Object.entries(attributes).forEach(([key, value]) => {
        if (key === 'className') {
            element.className = value;
        } else if (key === 'onclick') {
            element.addEventListener('click', value);
        } else {
            element.setAttribute(key, value);
        }
    });
    
    return element;
}

// Authentication Module
class AuthenticationManager {
    constructor() {
        this.token = null;
        this.user = null;
    }
    
    async authenticate() {
        try {
            const response = await fetch(SECURITY_CONFIG.authEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    [SECURITY_CONFIG.csrfTokenName]: csrfToken
                },
                body: JSON.stringify({ action: 'authenticate' })
            });
            
            if (!response.ok) {
                throw new Error('Authentication failed');
            }
            
            const data = await response.json();
            this.token = data.token;
            this.user = data.user;
            isAuthenticated = true;
            
            return true;
        } catch (error) {
            console.error('Authentication error:', error);
            this.handleAuthError(error);
            return false;
        }
    }
    
    handleAuthError(error) {
        const authOverlay = document.getElementById('authCheck');
        authOverlay.style.display = 'flex';
        
        const authButton = document.getElementById('authButton');
        authButton.addEventListener('click', () => {
            this.authenticate().then(success => {
                if (success) {
                    authOverlay.style.display = 'none';
                    initializeApp();
                }
            });
        });
    }
    
    isAuthenticated() {
        return isAuthenticated && this.token !== null;
    }
}

// API Client with CSRF Protection
class SecureAPIClient {
    constructor() {
        this.baseURL = SECURITY_CONFIG.apiEndpoint;
    }
    
    async fetchClients(query = '') {
        try {
            const sanitizedQuery = query ? validateAndSanitizeInput(query) : '';
            
            const response = await fetch(`${this.baseURL}?query=${encodeURIComponent(sanitizedQuery)}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${authManager.token}`,
                    [SECURITY_CONFIG.csrfTokenName]: csrfToken
                }
            });
            
            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }
            
            const data = await response.json();
            return this.validateClientData(data);
        } catch (error) {
            console.error('API fetch error:', error);
            throw error;
        }
    }
    
    validateClientData(data) {
        if (!Array.isArray(data)) {
            throw new Error('Invalid client data format');
        }
        
        return data.map(client => ({
            crossRefId: validateAndSanitizeInput(client.crossRefId || '', 20),
            clientType: validateAndSanitizeInput(client.clientType || '', 20),
            firstName: validateAndSanitizeInput(client.firstName || '', 50),
            lastName: validateAndSanitizeInput(client.lastName || '', 50),
            cod: validateAndSanitizeInput(client.cod || '', 20),
            uid: validateAndSanitizeInput(client.uid || '', 20)
        }));
    }
}

// Error Handler with Secure Logging
class SecureErrorHandler {
    static handle(error, context = '') {
        // Log detailed error securely (in production, this would go to a secure logging service)
        console.error(`[${context}] Secure error:`, {
            message: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent
        });
        
        // Show generic user-facing message
        this.showUserError('An error occurred. Please try again or contact support if the problem persists.');
    }
    
    static showUserError(message) {
        const tableSection = document.querySelector('.table-section');
        const errorDiv = safeCreateElement('div', '', {
            className: 'error-message',
            role: 'alert'
        });
        
        const errorText = safeCreateElement('strong', 'Error: ');
        const errorMessage = safeCreateElement('span', message);
        const retryButton = safeCreateElement('button', 'Retry', {
            className: 'retry-button',
            onclick: () => this.retry()
        });
        
        errorDiv.appendChild(errorText);
        errorDiv.appendChild(document.createElement('br'));
        errorDiv.appendChild(errorMessage);
        errorDiv.appendChild(document.createElement('br'));
        errorDiv.appendChild(retryButton);
        
        // Remove existing error messages
        const existingErrors = tableSection.querySelectorAll('.error-message');
        existingErrors.forEach(err => err.remove());
        
        tableSection.insertBefore(errorDiv, tableSection.firstChild);
    }
    
    static retry() {
        const errorMessage = document.querySelector('.error-message');
        if (errorMessage) {
            errorMessage.remove();
        }
        
        loadClientData();
    }
}

// Initialize authentication manager
const authManager = new AuthenticationManager();
const apiClient = new SecureAPIClient();

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    initializeCSRFToken();
    checkAuthentication();
});

// CSRF Token Management
function initializeCSRFToken() {
    // In a real application, this would come from the server
    csrfToken = generateCSRFToken();
    document.getElementById('csrfToken').value = csrfToken;
}

function generateCSRFToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Authentication Check
async function checkAuthentication() {
    if (!authManager.isAuthenticated()) {
        await authManager.authenticate();
    }
    
    if (authManager.isAuthenticated()) {
        initializeApp();
    }
}

// Initialize the application
async function initializeApp() {
    try {
        await loadClientData();
        renderTable(filteredData);
        setupEventListeners();
        updateRecordCount();
    } catch (error) {
        SecureErrorHandler.handle(error, 'App Initialization');
    }
}

// Load client data securely
async function loadClientData() {
    try {
        clientData = await apiClient.fetchClients();
        filteredData = [...clientData];
    } catch (error) {
        // Fallback to demo data for development
        console.warn('Using demo data due to API unavailability');
        clientData = getDemoData();
        filteredData = [...clientData];
    }
}

// Demo data (for development only)
function getDemoData() {
    return [
        { crossRefId: 'CR001', clientType: 'P10', firstName: 'John', lastName: 'Smith', cod: 'SD001', uid: 'UID001' },
        { crossRefId: 'CR002', clientType: 'P10', firstName: 'Sarah', lastName: 'Davis', cod: 'SD002', uid: 'UID002' },
        { crossRefId: 'CR003', clientType: 'P10', firstName: 'Michael', lastName: 'Johnson', cod: 'SD003', uid: 'UID003' },
        { crossRefId: 'CR004', clientType: 'P10', firstName: 'Emily', lastName: 'Williams', cod: 'SD004', uid: 'UID004' },
        { crossRefId: 'CR005', clientType: 'P10', firstName: 'David', lastName: 'Brown', cod: 'SD005', uid: 'UID005' },
        { crossRefId: 'CR006', clientType: 'P10', firstName: 'Jessica', lastName: 'Miller', cod: 'SD006', uid: 'UID006' },
        { crossRefId: 'CR007', clientType: 'P10', firstName: 'Daniel', lastName: 'Wilson', cod: 'SD007', uid: 'UID007' },
        { crossRefId: 'CR008', clientType: 'P10', firstName: 'Ashley', lastName: 'Moore', cod: 'SD008', uid: 'UID008' },
        { crossRefId: 'CR009', clientType: 'P10', firstName: 'Christopher', lastName: 'Taylor', cod: 'SD009', uid: 'UID009' },
        { crossRefId: 'CR010', clientType: 'P10', firstName: 'Amanda', lastName: 'Anderson', cod: 'SD010', uid: 'UID010' }
    ];
}

// Render table rows securely
function renderTable(data) {
    const tableBody = document.getElementById('clientTableBody');
    
    // Clear existing content
    while (tableBody.firstChild) {
        tableBody.removeChild(tableBody.firstChild);
    }
    
    if (data.length === 0) {
        const noDataRow = safeCreateElement('tr');
        const noDataCell = safeCreateElement('td', 'No client records found', {
            colspan: '7',
            style: 'text-align: center; padding: 40px; color: #999;'
        });
        noDataRow.appendChild(noDataCell);
        tableBody.appendChild(noDataRow);
        return;
    }
    
    data.forEach(client => {
        const row = safeCreateElement('tr');
        
        // Create cells with escaped content
        const cells = [
            safeCreateElement('td', escapeHtml(client.crossRefId)),
            safeCreateElement('td', escapeHtml(client.clientType)),
            safeCreateElement('td', escapeHtml(client.firstName)),
            safeCreateElement('td', escapeHtml(client.lastName)),
            safeCreateElement('td', escapeHtml(client.cod)),
            safeCreateElement('td', escapeHtml(client.uid))
        ];
        
        // Create action cell
        const actionCell = safeCreateElement('td');
        const viewButton = safeCreateElement('button', 'View', {
            className: 'btn-view',
            'aria-label': `View client ${escapeHtml(client.firstName)} ${escapeHtml(client.lastName)}`,
            onclick: () => viewClient(client.uid)
        });
        actionCell.appendChild(viewButton);
        
        // Append all cells to row
        cells.forEach(cell => row.appendChild(cell));
        row.appendChild(actionCell);
        
        tableBody.appendChild(row);
    });
}

// Setup event listeners
function setupEventListeners() {
    const searchInput = document.getElementById('searchInput');
    const clientTypeFilter = document.getElementById('clientTypeFilter');
    const advancedSearchBtn = document.querySelector('.btn-advanced-search');

    // Search input handler with validation
    searchInput.addEventListener('input', debounce((e) => {
        try {
            const validatedInput = validateAndSanitizeInput(e.target.value);
            handleSearch(validatedInput);
        } catch (error) {
            console.warn('Invalid search input:', error.message);
            // Clear invalid input
            e.target.value = '';
            handleSearch('');
        }
    }, 300));
    
    // Client type filter handler
    clientTypeFilter.addEventListener('change', handleSearch);
    
    // Advanced search button handler
    advancedSearchBtn.addEventListener('click', handleAdvancedSearch);
}

// Handle search functionality with validation
function handleSearch(searchTerm = '') {
    try {
        const validatedSearchTerm = searchTerm || validateAndSanitizeInput(
            document.getElementById('searchInput').value
        );
        const clientType = document.getElementById('clientTypeFilter').value;

        filteredData = clientData.filter(client => {
            const matchesSearch = !validatedSearchTerm || 
                client.crossRefId.toLowerCase().includes(validatedSearchTerm.toLowerCase()) ||
                client.firstName.toLowerCase().includes(validatedSearchTerm.toLowerCase()) ||
                client.lastName.toLowerCase().includes(validatedSearchTerm.toLowerCase()) ||
                client.cod.toLowerCase().includes(validatedSearchTerm.toLowerCase()) ||
                client.uid.toLowerCase().includes(validatedSearchTerm.toLowerCase());

            const matchesType = !clientType || client.clientType === clientType;

            return matchesSearch && matchesType;
        });

        renderTable(filteredData);
        updateRecordCount();
    } catch (error) {
        SecureErrorHandler.handle(error, 'Search');
    }
}

// Update record count
function updateRecordCount() {
    const recordCount = document.getElementById('recordCount');
    const totalCount = document.getElementById('totalCount');
    const badge = document.querySelector('.count-badge');
    
    recordCount.textContent = filteredData.length;
    totalCount.textContent = clientData.length;
    
    if (badge) {
        badge.textContent = filteredData.length;
    }
}

// View client handler with security
function viewClient(uid) {
    try {
        const validatedUid = validateAndSanitizeInput(uid, 20);
        const client = clientData.find(c => c.uid === validatedUid);
        
        if (client) {
            // Use secure modal instead of alert
            showClientModal(client);
        }
    } catch (error) {
        SecureErrorHandler.handle(error, 'View Client');
    }
}

// Secure client modal
function showClientModal(client) {
    // Remove existing modal
    const existingModal = document.querySelector('.client-modal');
    if (existingModal) {
        existingModal.remove();
    }
    
    const modal = safeCreateElement('div', '', {
        className: 'client-modal',
        style: 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;'
    });
    
    const modalContent = safeCreateElement('div', '', {
        className: 'modal-content',
        style: 'background: white; padding: 24px; border-radius: 8px; max-width: 400px; width: 90%;'
    });
    
    const title = safeCreateElement('h3', 'Client Details');
    const details = safeCreateElement('div', '', {
        style: 'margin: 16px 0;'
    });
    
    const detailFields = [
        `Name: ${escapeHtml(client.firstName)} ${escapeHtml(client.lastName)}`,
        `UID: ${escapeHtml(client.uid)}`,
        `Client Type: ${escapeHtml(client.clientType)}`,
        `Cross Reference ID: ${escapeHtml(client.crossRefId)}`
    ];
    
    detailFields.forEach(field => {
        const fieldDiv = safeCreateElement('div', field, {
            style: 'margin: 8px 0; padding: 8px; background: #f5f5f5; border-radius: 4px;'
        });
        details.appendChild(fieldDiv);
    });
    
    const closeButton = safeCreateElement('button', 'Close', {
        className: 'btn-view',
        style: 'margin-top: 16px;',
        onclick: () => modal.remove()
    });
    
    modalContent.appendChild(title);
    modalContent.appendChild(details);
    modalContent.appendChild(closeButton);
    modal.appendChild(modalContent);
    
    document.body.appendChild(modal);
    
    // Close on outside click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Advanced search handler
function handleAdvancedSearch() {
    showAdvancedSearchModal();
}

// Advanced search modal
function showAdvancedSearchModal() {
    const modal = safeCreateElement('div', '', {
        className: 'advanced-search-modal',
        style: 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;'
    });
    
    const modalContent = safeCreateElement('div', '', {
        className: 'modal-content',
        style: 'background: white; padding: 24px; border-radius: 8px; max-width: 500px; width: 90%;'
    });
    
    const title = safeCreateElement('h3', 'Advanced Search');
    const description = safeCreateElement('p', 'Advanced search options would include date range filters, multiple field search, complex query builder, and export options.', {
        style: 'margin: 16px 0; color: #666;'
    });
    
    const closeButton = safeCreateElement('button', 'Close', {
        className: 'btn-view',
        style: 'margin-top: 16px;',
        onclick: () => modal.remove()
    });
    
    modalContent.appendChild(title);
    modalContent.appendChild(description);
    modalContent.appendChild(closeButton);
    modal.appendChild(modalContent);
    
    document.body.appendChild(modal);
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Debounce utility function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Export functionality with security
function exportToCSV() {
    try {
        const headers = ['Cross Reference ID', 'Client Type', 'First Name', 'Last Name', 'COD', 'UID'];
        const csvContent = [
            headers.join(','),
            ...filteredData.map(client => 
                `"${escapeHtml(client.crossRefId)}","${escapeHtml(client.clientType)}","${escapeHtml(client.firstName)}","${escapeHtml(client.lastName)}","${escapeHtml(client.cod)}","${escapeHtml(client.uid)}"`
            )
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = window.URL.createObjectURL(blob);
        const a = safeCreateElement('a', '', {
            href: url,
            download: 'client-records.csv',
            style: 'display: none;'
        });
        
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        SecureErrorHandler.handle(error, 'Export');
    }
}

// Accessibility: Keyboard navigation for table
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        // Clear search
        document.getElementById('searchInput').value = '';
        document.getElementById('clientTypeFilter').value = '';
        handleSearch('');
        
        // Close any open modals
        const modals = document.querySelectorAll('.client-modal, .advanced-search-modal');
        modals.forEach(modal => modal.remove());
    }
});

// Security: Prevent right-click context menu on sensitive elements
document.addEventListener('contextmenu', (e) => {
    if (e.target.closest('.client-table') || e.target.closest('.client-modal')) {
        e.preventDefault();
    }
});

// Security: Prevent text selection on sensitive elements
document.addEventListener('selectstart', (e) => {
    if (e.target.closest('.client-table') && e.target.tagName !== 'INPUT') {
        e.preventDefault();
    }
});