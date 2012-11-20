/*File contains javascript/ Jquery that specifies the behavior of dialogs*/


$(function() {
        var params = $( "#params" );
        $( "#newCaptureDialog" ).dialog({
            autoOpen: false,
            height: 350,
            width: 800,
            modal: true,
            buttons: {
                "Create capture": function() {
                    newCapture(params.val());
                },
                Cancel: function() {
                    $( this ).dialog( "close" );
                }
            },
            close: function() {
                allFields.val( "" ).removeClass( "ui-state-error" );
            }
        });

        $( "#capturesDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

        var inputCapId = $( "#id" );
        $( "#changeCaptureDialog" ).dialog({
            autoOpen: false,
            height: 300,
            width: 800,
            modal: true,
            buttons: {
                "Follow capture": function() {
                    currentCapId = inputCapId.val();
                    $('#changeCaptureDialog').children("form").children("fieldset").children("p").html("Currently following: "+currentCapId);
                },
                Cancel: function() {
                    $( this ).dialog( "close" );
                }
            },
            close: function() {
                allFields.val( "" ).removeClass( "ui-state-error" );
            }
        });


        $( "#captureNotStoppedDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

        $( "#captureStoppedDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

        $( "#pollingBegunDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

        $( "#pollingPausedDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

        $( "#newCaptureCreatedDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

        $( "#newCaptureFailedDialog" ).dialog({
            autoOpen: false,
            height: 200,
            width: 500,
            modal: true
            });

    });
