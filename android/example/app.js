

var TiIdentity = require('ti.identity');

var win = Ti.UI.createWindow();

var btn = Ti.UI.createButton({
	title: 'authenticate'
});

win.add(btn);
win.open();

btn.addEventListener('click', function(){

	if (!TiIdentity.isSupported()) {
		alert("Touch ID is not supported on this device!");
		return;
	}

	TiIdentity.authenticate({
		title : "Biometric login for my app", // default: "Scan Fingerprint"
		subTitle : "Log in using your biometric credential", // optional
		cancelRaison : "Use account password", // default: "Cancel"
		callback: function(e) {
			if (!e.success) {
				alert('Message: ' + e.error);

			} else {
				alert('YAY! success');
			}
		}
	});

});
