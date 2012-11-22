
//Ask API to return all available captures
function getCaptures() {
    var r;
    $.ajax({
       url: '/captures/',
       type: 'GET',
       success: function(response) {
            $('#response').append(response);
       }
    });
}

//Ask for the output of a specified capture
function getCapture(id) {
    $.ajax({
       url: '/captures/'+id,
       type: 'GET',
       success: function(response) {
        $('#response').append(response);
       }
    });
}

//Ask for creation of a new capture
function createCapture(params) {
    $.ajax({
       url: '/captures/',
       type: 'POST',
       success: function(response) {
         $('#response').append(response);
       }
    });
}

//Ask for all captures to be stopped
function endCaptures() {
    $.ajax({
       url: '/captures/',
       type: 'DELETE',
       success: function(response) {
         $('#response').append(response);
       }
    });
}

//Ask for a specified capture to be stopped
function endCapture(id) {
    $.ajax({
       url: '/captures/'+id,
       type: 'DELETE',
       success: function(response) {
         $('#response').append(response);
       }
    });
}

