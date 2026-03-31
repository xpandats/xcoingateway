// ===== XCOINGATEWAY LANDING PAGE - ANIMATIONS & INTERACTIONS =====

document.addEventListener('DOMContentLoaded', () => {
    initParticleNetwork();
    initScrollReveal();
    initNavbar();
    initMobileMenu();
    initCounterAnimation();
    initSmoothScroll();
    initChainCardHover();
    initTypingEffect();
});

// ===== 1. PARTICLE NETWORK ANIMATION =====
function initParticleNetwork() {
    const canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    let particles = [];
    let mouse = { x: null, y: null, radius: 150 };
    let animationId;

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    resize();
    window.addEventListener('resize', debounce(resize, 200));

    window.addEventListener('mousemove', (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    window.addEventListener('mouseout', () => {
        mouse.x = null;
        mouse.y = null;
    });

    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.size = Math.random() * 2 + 0.5;
            this.speedX = (Math.random() - 0.5) * 0.5;
            this.speedY = (Math.random() - 0.5) * 0.5;
            this.opacity = Math.random() * 0.5 + 0.1;
            // Random color between teal and purple
            this.hue = Math.random() > 0.5 ? 160 : 265;
            this.saturation = 80 + Math.random() * 20;
            this.lightness = 50 + Math.random() * 20;
        }

        update() {
            this.x += this.speedX;
            this.y += this.speedY;

            // Mouse interaction
            if (mouse.x !== null && mouse.y !== null) {
                const dx = mouse.x - this.x;
                const dy = mouse.y - this.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < mouse.radius) {
                    const force = (mouse.radius - dist) / mouse.radius;
                    this.x -= (dx / dist) * force * 1.5;
                    this.y -= (dy / dist) * force * 1.5;
                }
            }

            // Wrap around
            if (this.x > canvas.width + 10) this.x = -10;
            if (this.x < -10) this.x = canvas.width + 10;
            if (this.y > canvas.height + 10) this.y = -10;
            if (this.y < -10) this.y = canvas.height + 10;
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fillStyle = `hsla(${this.hue}, ${this.saturation}%, ${this.lightness}%, ${this.opacity})`;
            ctx.fill();
        }
    }

    function createParticles() {
        const count = Math.min(Math.floor((canvas.width * canvas.height) / 12000), 120);
        particles = [];
        for (let i = 0; i < count; i++) {
            particles.push(new Particle());
        }
    }

    function connectParticles() {
        const maxDist = 140;
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < maxDist) {
                    const opacity = (1 - dist / maxDist) * 0.15;
                    const gradient = ctx.createLinearGradient(
                        particles[i].x, particles[i].y,
                        particles[j].x, particles[j].y
                    );
                    gradient.addColorStop(0, `hsla(${particles[i].hue}, 80%, 60%, ${opacity})`);
                    gradient.addColorStop(1, `hsla(${particles[j].hue}, 80%, 60%, ${opacity})`);
                    
                    ctx.beginPath();
                    ctx.strokeStyle = gradient;
                    ctx.lineWidth = 0.6;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        particles.forEach(p => {
            p.update();
            p.draw();
        });
        connectParticles();
        animationId = requestAnimationFrame(animate);
    }

    createParticles();
    animate();

    // Recreate on resize
    window.addEventListener('resize', debounce(() => {
        createParticles();
    }, 300));
}

// ===== 2. SCROLL REVEAL ANIMATION =====
function initScrollReveal() {
    const revealElements = document.querySelectorAll('.reveal-up');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                // Don't unobserve - keep watching for re-entry if needed
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -60px 0px'
    });

    revealElements.forEach(el => observer.observe(el));
}

// ===== 3. NAVBAR SCROLL BEHAVIOR =====
function initNavbar() {
    const navbar = document.getElementById('navbar');
    let lastScroll = 0;

    window.addEventListener('scroll', () => {
        const currentScroll = window.scrollY;
        
        if (currentScroll > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }

        lastScroll = currentScroll;
    }, { passive: true });
}

// ===== 4. MOBILE MENU =====
function initMobileMenu() {
    const toggle = document.getElementById('mobileToggle');
    const menu = document.getElementById('mobileMenu');
    const links = menu?.querySelectorAll('.mobile-link');

    if (!toggle || !menu) return;

    toggle.addEventListener('click', () => {
        toggle.classList.toggle('active');
        menu.classList.toggle('active');
        document.body.style.overflow = menu.classList.contains('active') ? 'hidden' : '';
    });

    links?.forEach(link => {
        link.addEventListener('click', () => {
            toggle.classList.remove('active');
            menu.classList.remove('active');
            document.body.style.overflow = '';
        });
    });
}

// ===== 5. COUNTER ANIMATION =====
function initCounterAnimation() {
    const counters = document.querySelectorAll('.stat-number[data-count]');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !entry.target.dataset.animated) {
                entry.target.dataset.animated = 'true';
                animateCounter(entry.target);
            }
        });
    }, { threshold: 0.5 });

    counters.forEach(counter => observer.observe(counter));
}

function animateCounter(element) {
    const target = parseInt(element.dataset.count);
    const duration = 2000;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.floor(eased * target);

        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = target;
        }
    }

    requestAnimationFrame(update);
}

// ===== 6. SMOOTH SCROLL =====
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                e.preventDefault();
                const offset = 80; // navbar height
                const top = target.getBoundingClientRect().top + window.scrollY - offset;
                
                window.scrollTo({
                    top: top,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// ===== 7. CHAIN CARD HOVER EFFECTS =====
function initChainCardHover() {
    const cards = document.querySelectorAll('.chain-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            // Add subtle glow based on chain color
            this.style.setProperty('--card-glow', '0 0 40px rgba(0,229,160,0.2)');
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.removeProperty('--card-glow');
        });
    });

    // Feature cards tilt effect
    const featureCards = document.querySelectorAll('.feature-card');
    
    featureCards.forEach(card => {
        card.addEventListener('mousemove', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            const rotateX = (y - centerY) / centerY * -3;
            const rotateY = (x - centerX) / centerX * 3;
            
            this.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-4px)`;
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
}

// ===== 8. CODE TYPING EFFECT =====
function initTypingEffect() {
    const codeBlocks = document.querySelectorAll('.code-block pre code');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !entry.target.dataset.typed) {
                entry.target.dataset.typed = 'true';
                typeCode(entry.target);
            }
        });
    }, { threshold: 0.3 });

    codeBlocks.forEach(block => observer.observe(block));
}

function typeCode(element) {
    const originalHTML = element.innerHTML;
    const text = element.textContent;
    element.innerHTML = '';
    element.style.opacity = '1';
    
    let charIndex = 0;
    const speed = 15; // ms per character
    
    function type() {
        if (charIndex < text.length) {
            // For performance, add chars in chunks
            const chunk = Math.min(3, text.length - charIndex);
            charIndex += chunk;
            element.innerHTML = originalHTML.substring(0, getHTMLIndex(originalHTML, charIndex));
            requestAnimationFrame(() => setTimeout(type, speed));
        } else {
            element.innerHTML = originalHTML;
        }
    }
    
    // Quick fade in instead of character-by-character for complex HTML
    element.style.opacity = '0';
    element.innerHTML = originalHTML;
    element.style.transition = 'opacity 0.8s ease';
    requestAnimationFrame(() => {
        element.style.opacity = '1';
    });
}

function getHTMLIndex(html, textIndex) {
    let textCount = 0;
    let inTag = false;
    
    for (let i = 0; i < html.length; i++) {
        if (html[i] === '<') inTag = true;
        if (!inTag) textCount++;
        if (html[i] === '>') inTag = false;
        if (textCount >= textIndex) return i + 1;
    }
    return html.length;
}

// ===== UTILITY: DEBOUNCE =====
function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// ===== PARALLAX EFFECT ON SCROLL =====
window.addEventListener('scroll', () => {
    const scrolled = window.scrollY;
    
    // Subtle parallax on orbs
    const orbs = document.querySelectorAll('.ambient-orb');
    orbs.forEach((orb, index) => {
        const speed = 0.02 + index * 0.01;
        orb.style.transform += ` translateY(${scrolled * speed}px)`;
    });
}, { passive: true });

// ===== INTERSECTION OBSERVER FOR FLOW CARDS (STAGGER) =====
const flowCards = document.querySelectorAll('.flow-card');
const flowObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry, index) => {
        if (entry.isIntersecting) {
            entry.target.style.animationPlayState = 'running';
        }
    });
}, { threshold: 0.2 });

flowCards.forEach(card => {
    card.style.animationPlayState = 'paused';
    flowObserver.observe(card);
});
