//Ask API to return all available captures
function ajaxGetCaptures(callback) {
    var r;
    $.ajax({
       url: '/captures/',
       type: 'GET',
       success: callback
    });
}

//Ask for the output of a specified capture
function ajaxGetCapture(callback, id) {
    $.ajax({
       url: '/captures/'+id,
       type: 'GET',
       success: callback
    });
}

//Ask for creation of a new capture
function ajaxNewCapture(callback, params) {
    $.ajax({
       url: '/captures/new/'+params,
       type: 'POST',
       success: callback
    });
}

//Ask for all captures to be stopped
function ajaxEndCaptures(callback) {
    $.ajax({
       url: '/captures/',
       type: 'DELETE',
       success: callback
    });
}

//Ask for a specified capture to be stopped
function ajaxEndCapture(callback, id) {
    $.ajax({
       url: '/captures/'+id,
       type: 'DELETE',
       success: callback
    });
}

