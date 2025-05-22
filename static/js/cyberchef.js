// Initialize CyberChef when the iframe loads
window.addEventListener('message', function(event) {
    if (event.data.type === 'runRecipe') {
        const chef = event.source.Chef;
        if (chef) {
            try {
                const result = chef.bake(event.data.input, event.data.recipe);
                event.source.postMessage({
                    type: 'recipeResult',
                    result: result
                }, '*');
            } catch (error) {
                event.source.postMessage({
                    type: 'recipeResult',
                    result: 'Error: ' + error.message
                }, '*');
            }
        }
    }
});

// Handle recipe loading
window.addEventListener('message', function(event) {
    if (event.data.type === 'loadRecipe') {
        const chef = event.source.Chef;
        if (chef) {
            try {
                chef.setRecipe(event.data.recipe);
                event.source.postMessage({
                    type: 'recipeLoaded',
                    success: true
                }, '*');
            } catch (error) {
                event.source.postMessage({
                    type: 'recipeLoaded',
                    success: false,
                    error: error.message
                }, '*');
            }
        }
    }
}); 