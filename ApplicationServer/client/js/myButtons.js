/*File contains javascript/ Jquery that specifies behavior of buttons*/

$(function() {
    $( "#btNew" ).button({
        icons: {
            primary: "ui-icon-circle-plus"
        }
    }).click(function(){$("#newCaptureDialog").dialog("open");});

    $( "#btEnd" ).button({
        icons: {
            primary: "ui-icon-closethick"
        }
    });

    $( "#btStartStop" ).button({
        icons: {
            primary: "ui-icon-play"
        }
    })
    .click(function() {
        var options;
        if ( $( this ).text() === "start" ) {
            options = {
                label: "stop",
                icons: {
                    primary: "ui-icon-pause"
                }
            };
        } else {
            options = {
                label: "start",
                icons: {
                    primary: "ui-icon-play"
                }
            };
        }
        $( this ).button( "option", options );
    });

    $( "#btMore" ).button({
        icons: {
            primary: "ui-icon-arrowrefresh-1-s"
        }
    });

    $( "#btEndAll" ).button({
        icons: {
            primary: "ui-icon-trash"
        }
    });

    $( "#btListCaptures" ).button({
        icons: {
            primary: "ui-icon-script"
        }
    }).click(function(){
                        $("#capturesDialog").dialog("open");
                        listCaptures();
                       });


    $( "#btChangeCapture" ).button({
            icons: {
                primary: "ui-icon-newwin"
            }
        }).click(function(){
      	                    $('#changeCaptureDialog').children("form").children("fieldset").children("p").html("Currently following: "+currentCapId);
                            $("#changeCaptureDialog").dialog("open");
                           });


});

