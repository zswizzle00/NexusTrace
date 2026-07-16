// Mobile-specific enhancements for NexusTrace

document.addEventListener('DOMContentLoaded', function() {
    
    // Prevent zoom on double tap for iOS
    let lastTouchEnd = 0;
    document.addEventListener('touchend', function (event) {
        const now = (new Date()).getTime();
        if (now - lastTouchEnd <= 300) {
            event.preventDefault();
        }
        lastTouchEnd = now;
    }, false);

    // Add touch feedback to buttons and cards
    const touchElements = document.querySelectorAll('.btn, .feature-card, .card');
    
    touchElements.forEach(element => {
        element.addEventListener('touchstart', function() {
            this.style.transform = 'scale(0.98)';
            this.style.transition = 'transform 0.1s ease';
        });
        
        element.addEventListener('touchend', function() {
            this.style.transform = '';
            this.style.transition = '';
        });
        
        element.addEventListener('touchcancel', function() {
            this.style.transform = '';
            this.style.transition = '';
        });
    });

    // Improve form input experience on mobile
    const inputs = document.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        // Prevent zoom on focus for iOS
        input.addEventListener('focus', function() {
            if (window.innerWidth <= 768) {
                this.style.fontSize = '16px';
            }
        });
        
        // Add visual feedback
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('input-focused');
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('input-focused');
        });
    });

    // Show a loading spinner on the submit button for the duration of the server round-trip.
    // These are full-page POST requests so the page navigates away when the response arrives —
    // no need to reset the button ourselves. The only case we need to handle is the user
    // pressing Back, which restores the page from bfcache with the button still disabled.
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                // Fallback: re-enable after 90s in case the server never responds
                // (gunicorn --timeout is 120s; this gives a visible recovery window)
                setTimeout(() => {
                    submitBtn.classList.remove('loading');
                    submitBtn.disabled = false;
                }, 90000);
            }
        });
    });

    // Reset any stuck loading buttons when the browser restores this page from bfcache
    // (fires when the user navigates back and the page was preserved in memory).
    window.addEventListener('pageshow', function(event) {
        if (event.persisted) {
            document.querySelectorAll('button[type="submit"].loading').forEach(function(btn) {
                btn.classList.remove('loading');
                btn.disabled = false;
            });
        }
    });

    // Add haptic feedback for supported devices
    function hapticFeedback() {
        if ('vibrate' in navigator) {
            navigator.vibrate(50);
        }
    }
    
    // Add haptic feedback to important interactions
    const hapticElements = document.querySelectorAll('.btn-primary, .feature-card');
    
    hapticElements.forEach(element => {
        element.addEventListener('click', hapticFeedback);
    });

    // Optimize images for mobile
    const images = document.querySelectorAll('img');
    
    images.forEach(img => {
        // Add lazy loading for better performance
        img.loading = 'lazy';
        
        // Add error handling
        img.addEventListener('error', function() {
            this.style.display = 'none';
        });
    });

    // Add mobile-specific CSS classes
    function updateMobileClasses() {
        const isMobile = window.innerWidth <= 768;
        const isTablet = window.innerWidth > 768 && window.innerWidth <= 1024;
        
        document.body.classList.toggle('mobile', isMobile);
        document.body.classList.toggle('tablet', isTablet);
        document.body.classList.toggle('desktop', window.innerWidth > 1024);
    }
    
    // Initial call
    updateMobileClasses();
    
    // Update on resize
    window.addEventListener('resize', updateMobileClasses);

    // Add keyboard navigation support for mobile
    document.addEventListener('keydown', function(e) {
        // Handle escape key to close modals or dropdowns
        if (e.key === 'Escape') {
            const activeDropdowns = document.querySelectorAll('.dropdown-content.show');
            activeDropdowns.forEach(dropdown => {
                dropdown.classList.remove('show');
            });
        }
    });

    // Improve accessibility for mobile
    const focusableElements = document.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    
    // Add better focus indicators for mobile
    focusableElements.forEach(element => {
        element.addEventListener('focus', function() {
            this.style.outline = '2px solid #3B82F6';
            this.style.outlineOffset = '2px';
        });
        
        element.addEventListener('blur', function() {
            this.style.outline = '';
            this.style.outlineOffset = '';
        });
    });

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(() => {});
    }
});

// Add mobile-specific utility functions
window.mobileUtils = {
    // Check if device is mobile
    isMobile: function() {
        return window.innerWidth <= 768;
    },
    
    // Check if device supports touch
    isTouchDevice: function() {
        return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    },
    
    // Get device pixel ratio
    getPixelRatio: function() {
        return window.devicePixelRatio || 1;
    },
    
    // Format file size for mobile display
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}; 