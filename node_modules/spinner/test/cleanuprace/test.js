var spinner = require('../..').createSpinner();

spinner.start('./normal.js');
spinner.start('./dontwanttodie.js', function(err) {
	console.error('>>>>>', err);
});

