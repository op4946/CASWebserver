function watchColorPicker() {
	document.querySelectorAll('label').forEach(function(p) {
		p.style.border = "solid "+ event.target.value;
		p.style.color = event.target.value;
		//getRuleWithSelector('label::after').style.border = "solid " + event.target.value;
		document.styleSheets[1].cssRules[13].style.border = "solid " + event.target.value;
	})
}
