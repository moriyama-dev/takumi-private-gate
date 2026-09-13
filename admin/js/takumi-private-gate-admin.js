( function () {
	'use strict';

	document.querySelectorAll( '.prvgate-settings input[type="number"]' ).forEach( function ( input ) {
		input.addEventListener( 'change', function () {
			if ( parseInt( input.value, 10 ) < 1 || isNaN( parseInt( input.value, 10 ) ) ) {
				input.value = 1;
			}
		} );
	} );
} )();
