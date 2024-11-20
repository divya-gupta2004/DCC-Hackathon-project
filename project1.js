// Smooth Scroll Functionality
document.querySelectorAll('nav ul li a').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Hide Welcome Screen and Show Main Content
function startApp() {
    document.getElementById('welcome-screen').style.display = 'none';
}