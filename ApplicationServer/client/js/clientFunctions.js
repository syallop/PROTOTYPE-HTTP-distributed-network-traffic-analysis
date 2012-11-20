var currentCapId;   //ID of current capture to request packets from
var running = false;//Whether to ask for more packets
var delay = 10000;  //Miliseconds to wait before asking for more packets
var loopMorePackets;//looping poll

//Ask the server to create a new capture, store the id returned in currentCapId
function newCapture() {
    function newCaptureCallback(response){
        if (response == "0"){
            alert("Server did not create a new capture.");
        } else {
            currentCapId = response;
            alert("Server created new capture with ID: "+response);
        }
    }
    //Ask user for parameters, POST to server
    ajaxNewCapture(newCaptureCallback, "static packets.pcap none 0");
}





//Ask the server to end a capture with the specified id
function endCapture(capId) {
    function endCaptureCallback(response){
        if(response == "success"){
            alert("Server reported it stopped the capture.");
        } else {
            alert("Server reported it did not end the capture");
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
    ajaxEndCaptures(dumpResponse);
}




//Ask the server to report all captures it knows about
function listCaptures(){
    ajaxGetCaptures(dumpResponse);
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
        alert("Stopped polling for new packets.");
    } else {
        loopMorePackets = setInterval(getMorePackets, delay);
        running = true;
        alert("Started polling for new packets every "+delay+" miliseconds.");
    }
}

