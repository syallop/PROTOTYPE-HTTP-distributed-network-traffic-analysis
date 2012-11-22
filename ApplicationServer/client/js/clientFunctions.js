/*File contains the core functions called by a client*/


var currentCapId = 0;   //ID of current capture to request packets from
var running = false;//Whether to ask for more packets
var delay = 10000;  //Miliseconds to wait before asking for more packets
var loopMorePackets;//looping poll

//Ask the server to create a new capture, store the id returned in currentCapId
function newCapture(params){
    function newCaptureCallback(response){
        if (response == "0"){
            $("#newCaptureFailedDialog").dialog("open");
        } else {
            currentCapId = response;
	        $('#newCaptureCreatedDialog').children("p").html("New capture with ID: "+currentCapId);
            $("#newCaptureCreatedDialog").dialog("open");
        }
    }
    //Ask user for parameters, POST to server
    ajaxNewCapture(newCaptureCallback, params);

}



//Ask the server to end a capture with the specified id
function endCapture(capId) {
    function endCaptureCallback(response){
        if(response == "success"){
	    $("#captureStoppedDialog").dialog("open");
        } else {
            $("#captureNotStoppedDialog").dialog("open");
        }
    }
    ajaxEndCapture(endCaptureCallback, capId);
}
//Ask the server to end our current capture
function endCurrentCapture() {
    endCapture(currentCapId);
}
//Ask the server to end all captures it knows about
function endAllCaptures() {
    function endAllCapturesCallback(response){
        if(response == "success"){
	        $("#captureStoppedDialog").dialog("open");
        } else {
            $("#captureNotStoppedDialog").dialog("open");
        }
    }
    ajaxEndCaptures(endAllCapturesCallback);
}




//Ask the server to report all captures it knows about
function listCaptures(){
    function listCapturesCallback(response){
	$('#capturesDialog').children("p").html(response);
    }
    ajaxGetCaptures(listCapturesCallback);
}



//Ask the server for more packets from our monitored capture
function getMorePackets(){
    function getMorePacketsCallback(packetsListString){
        var packetsList = jQuery.parseJSON(packetsListString);
        var output = showJsonPacketsList(packetsList);

        $('#packets').append(output);
        $('#packets').animate({scrollTop:$("#packets")[0].scrollHeight}, 1000);
    }

    ajaxGetCapture(getMorePacketsCallback, currentCapId);
}

//If polling for packets, stop that, otherwise, start..
function toggleStartStop() {
    if(running){
        loopMorePackets = window.clearInterval(loopMorePackets);
        running = false;
        $("#pollingPausedDialog").dialog("open");
    } else {
        loopMorePackets = setInterval(getMorePackets, delay);
        running = true;
        $("#pollingBegunDialog").dialog("open");
    }
}

