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

    // Add swipe gestures for navigation (if needed)
    let startX = 0;
    let startY = 0;
    
    document.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
    });
    
    document.addEventListener('touchend', function(e) {
        if (!startX || !startY) return;
        
        const endX = e.changedTouches[0].clientX;
        const endY = e.changedTouches[0].clientY;
        
        const diffX = startX - endX;
        const diffY = startY - endY;
        
        // Only handle horizontal swipes
        if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 50) {
            // Swipe left or right detected
            // You can add navigation logic here if needed
        }
        
        startX = 0;
        startY = 0;
    });

    // Optimize scrolling performance
    let ticking = false;
    
    function updateScroll() {
        // Add any scroll-based animations here
        ticking = false;
    }
    
    document.addEventListener('scroll', function() {
        if (!ticking) {
            requestAnimationFrame(updateScroll);
            ticking = true;
        }
    });

    // Add loading states for better UX
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                
                // Re-enable after a timeout (in case of errors)
                setTimeout(() => {
                    submitBtn.classList.remove('loading');
                    submitBtn.disabled = false;
                }, 10000);
            }
        });
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

    // Add mobile-specific error handling
    window.addEventListener('error', function(e) {
        console.error('Mobile error:', e.error);
        // You can add error reporting here
    });

    // Optimize for mobile performance
    if ('serviceWorker' in navigator) {
        // Register service worker for offline functionality
        navigator.serviceWorker.register('/sw.js')
            .then(registration => {
                console.log('SW registered: ', registration);
            })
            .catch(registrationError => {
                console.log('SW registration failed: ', registrationError);
            });
    }

    // Add mobile-specific analytics or tracking
    function trackMobileUsage() {
        const userAgent = navigator.userAgent;
        const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
        
        if (isMobile) {
            // Track mobile usage
            console.log('Mobile user detected');
        }
    }
    
    trackMobileUsage();
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