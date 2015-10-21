require('shelljs/global');

var Firebase = require('firebase');
var ref = new Firebase('https://voltaire-doorman.firebaseio.com');

// var TIME_FRAME = 3 * 60 * 60 * 1000; // 3 hours
var TIME_FRAME = 30 * 1000;
var LAST_STATUS = null;

function getPrevious(mac) {
    for (var i = 0; i < LAST_STATUS.length; i++) {
        if (LAST_STATUS[i]['mac'] == mac) {
            return LAST_STATUS[i];
        }
    }
    return null;
}

function playSound(mac) {
    // exec('afplay intro.mp3'); for mac
    exec('omxplayer intro.mp3');
}


function onChange (status) {
    status = status.val();
    console.log('Change Status', status);
    if (!LAST_STATUS) {
        LAST_STATUS = status;
    }

    for (var i = 0; i < status.length; i++) {
        var seen = new Date(status[i]['last_seen']);

        var previousStatus = getPrevious(status[i]['mac']);
        var previousSeen = previousStatus && new Date(previousStatus['last_seen']);
        if (!previousStatus || seen - previousSeen > TIME_FRAME) {
            
            console.log('[CHECKING] Play sound for', status[i]);
            playSound(status[i]['mac']);
        }
    }
    LAST_STATUS = status;
}

function onError (error) {
    console.log('Error', error.code);
}


ref.child('status').on('value', onChange, onError);
