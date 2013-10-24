// Adapted from the patch for mozTCPSocket error reporting (bug 861196).

let Cc = Components.classes;
let Ci = Components.interfaces;

function createTCPErrorFromFailedXHR(xhr) 
{
  let status = xhr.channel.QueryInterface(Ci.nsIRequest).status;
   
  if ((status & 0xff0000) === 0x5a0000) { // Security error
  	return status;
  } else {
	/*Network error*/
	return -1;
  }

}

function connect(url) 
{
  var req = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
  req.mozBackgroundRequest=true;
  req.open('GET', url, true);
  req.addEventListener("error",
                       function(e) {
                         var error = createTCPErrorFromFailedXHR(req);
                         dump('return val= '+error+'\n');
			 quit(1);
                       },
                       true);
 
  req.onload = function(e) {
    dump('return val= 0\n');
    quit(1);
  };

  req.send();
}

function quit (fQuit)
{
  var as = Components.classes['@mozilla.org/toolkit/app-startup;1'].
    getService(Components.interfaces.nsIAppStartup);

  var qSeverity = fQuit ? Components.interfaces.nsIAppStartup.eForceQuit :
                         Components.interfaces.nsIAppStartup.eAttemptQuit;
  as.quit(qSeverity);
}

function onWindowLoad() 
{
  var cmdLine = window.arguments[0];
  cmdLine = cmdLine.QueryInterface(Components.interfaces.nsICommandLine);
  if (cmdLine.length<2) {
    dump("Usage: xulrunner application.ini host port\n");
    quit(1);
  }
  hostname=cmdLine.getArgument(0);
  port = cmdLine.getArgument(1);
  connect("https://"+hostname+":"+port+"/");
}
