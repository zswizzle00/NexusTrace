
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

    const inputs = document.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        // Prevent zoom on focus for iOS
        input.addEventListener('focus', function() {
            if (window.innerWidth <= 768) {
                this.style.fontSize = '16px';
            }
        });
        
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('input-focused');
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('input-focused');
        });
    });

    // Full-page POSTs, so the page navigates away and the button never needs resetting on
    // success. The case that does need handling is Back restoring it from bfcache disabled.
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                // Re-enable before gunicorn's 120s --timeout so a hung server still leaves
                // a visible recovery window.
                setTimeout(() => {
                    submitBtn.classList.remove('loading');
                    submitBtn.disabled = false;
                }, 90000);
            }
        });
    });

    // Reset buttons left stuck in 'loading' when Back restores the page from bfcache.
    window.addEventListener('pageshow', function(event) {
        if (event.persisted) {
            document.querySelectorAll('button[type="submit"].loading').forEach(function(btn) {
                btn.classList.remove('loading');
                btn.disabled = false;
            });
        }
    });

    function hapticFeedback() {
        if ('vibrate' in navigator) {
            navigator.vibrate(50);
        }
    }
    
    const hapticElements = document.querySelectorAll('.btn-primary, .feature-card');
    
    hapticElements.forEach(element => {
        element.addEventListener('click', hapticFeedback);
    });

    const images = document.querySelectorAll('img');
    
    images.forEach(img => {
        img.loading = 'lazy';
        
        img.addEventListener('error', function() {
            this.style.display = 'none';
        });
    });

    function updateMobileClasses() {
        const isMobile = window.innerWidth <= 768;
        const isTablet = window.innerWidth > 768 && window.innerWidth <= 1024;
        
        document.body.classList.toggle('mobile', isMobile);
        document.body.classList.toggle('tablet', isTablet);
        document.body.classList.toggle('desktop', window.innerWidth > 1024);
    }
    
    updateMobileClasses();
    
    window.addEventListener('resize', updateMobileClasses);

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const activeDropdowns = document.querySelectorAll('.dropdown-content.show');
            activeDropdowns.forEach(dropdown => {
                dropdown.classList.remove('show');
            });
        }
    });

    const focusableElements = document.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    
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

window.mobileUtils = {
    isMobile: function() {
        return window.innerWidth <= 768;
    },
    
    isTouchDevice: function() {
        return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    },
    
    getPixelRatio: function() {
        return window.devicePixelRatio || 1;
    },
    
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}; 