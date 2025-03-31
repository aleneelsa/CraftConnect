document.addEventListener("DOMContentLoaded", function () {
    let currentSlide = 0;
    const slides = document.querySelectorAll(".slide");

    if (slides.length === 0) {
        console.error("No images found! Check your paths.");
        return;
    }

    console.log("Slideshow started with " + slides.length + " images."); // Debugging

    function showSlide() {
        // Hide all slides
        slides.forEach((slide, index) => {
            slide.style.opacity = "0";
            slide.style.position = "absolute"; // Stack them
        });

        // Show only the current slide
        slides[currentSlide].style.opacity = "1";
        slides[currentSlide].style.position = "relative"; // Make it visible

        // Move to the next slide
        currentSlide = (currentSlide + 1) % slides.length;
    }

    // Show first image immediately
    showSlide();

    // Start slideshow every 3 seconds
    setInterval(showSlide, 3000);
});
